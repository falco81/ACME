#!/usr/bin/python3 -I
"""acme_web.py - the web side of a node, put in place by root (1.0.47).

Two things the pages may ask for that need root, both about HTTPS:

  * TLS - the certificate (with its chain, and the root it is checked
    against), the protocols, the ciphers and the DH parameters nginx uses:
    for this node's own name, and for the cluster's web address;
  * the cluster's web address (VIP): one more address the pages and the
    administration answer on, on one node at a time - active/standby - held
    by keepalived (VRRP). acme writes /run/acme/vip-state every few seconds
    and keepalived asks /usr/libexec/keepalived/acme-vip-check whether this node
    may hold it (acme answering, not in maintenance, not being upgraded) and
    whether it is the one preferred; it moves the address by itself when
    that changes, or when the other node is gone. RADIUS never uses it:
    both nodes go on answering RADIUS on their own addresses.

The daemon runs as `acme` and may not do any of this: it lays a request down
in /var/lib/acme/web/request.json and systemd (acme-web.path) starts this as
root. Nothing in the request is trusted: every value is checked against the
one shape it may have before it goes into a file, certificates and keys are
read by openssl, nginx is asked (nginx -t) before it is reloaded and put
back as it was when it says no, and the folder is used through one
descriptor, never a path the acme account could swap for a link.

  acme_web.py            serve request.json (as root, from systemd)
  acme_web.py --status   what is in place here (JSON)
  acme_web.py --os-job ID check|upgrade   the system's updates (started by itself)
  acme_web.py --sshd-back                 a change of sshd on trial put back (its timer)
  acme_web.py --dbmake                    a database and its account made here (JSON on stdin)
  acme_web.py --selinux-check [--want-stdin] [--json]   how SELinux stands for acme here
  acme_web.py --selinux-do STEP           prepare|apply|enforce|permissive (what acme needs on stdin)
  acme_web.py --selinux-report FILE       what SELinux says here, for acme's module (a .tar.gz)
"""
import errno
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

STATE_DIR = os.environ.get('ACME_STATE', '/var/lib/acme')
WEB_DIR = os.path.join(STATE_DIR, 'web')
KA_CONF = os.environ.get('ACME_VIP_KA_CONF', '/etc/keepalived/keepalived.conf')
NGINX_DIR = os.environ.get('ACME_VIP_NGINX_DIR', '/etc/nginx/conf.d')
NGINX_MAIN = os.path.join(NGINX_DIR, 'acme.conf')
NGINX_VIP = os.path.join(NGINX_DIR, 'acme_vip.conf')   # read after acme.conf: never the default server
CERT_DIR = os.environ.get('ACME_VIP_CERT_DIR', '/etc/nginx/certs')
# Where SELinux lets keepalived run it; the program's own folder otherwise.
CHECK = os.environ.get('ACME_VIP_CHECK') or next(
    (p for p in ('/usr/libexec/keepalived/acme-vip-check', '/usr/local/lib/acme/acme-vip-check')
     if os.access(p, os.X_OK)), '/usr/libexec/keepalived/acme-vip-check')
NO_SERVICES = bool(os.environ.get('ACME_VIP_NO_SERVICES'))      # tests: no systemctl
PGLOG_ASK = 'pglog.ask'
PGTLS_ASK = 'pgtls.ask'          # the link between the two databases (1.0.104)
PGTLS_FILE = 'pgtls.json'
HA_CA_FILE = os.environ.get('ACME_HA_CA', '/etc/pki/acme/ha-ca.pem')
PG_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
PG_HBA_WORDS = ('all', 'sameuser', 'samerole', 'samegroup', 'replication')
PGLOG_FILE = 'pglog.json'
MARK = '# written by acme (acme_web.py) - acme keeps this file; change it on its pages'


ADDR_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z')


def plain(text, how):
    """An address, a network or an address with its prefix - and nothing
    else (1.0.57): ipaddress keeps an IPv6 scope id (fe80::1%eth0) with any
    character in it, newlines and braces included, and so into nginx,
    keepalived and ip6tables files root writes."""
    text = str(text or '').strip()
    if not ADDR_RE.match(text):
        raise ValueError('not a plain address')
    got = {'address': ipaddress.ip_address, 'network': lambda t: ipaddress.ip_network(t, strict=False),
           'interface': ipaddress.ip_interface}[how](text)
    if '%' in str(got):
        raise ValueError('a scope id is not taken')
    return got


class Refused(Exception):
    pass


# ---- the folder the acme account owns: one descriptor, never a path -----------------
FD = [None]


def web_fd():
    if FD[0] is None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        top = os.open(STATE_DIR, flags)
        try:
            FD[0] = os.open('web', flags, dir_fd=top)
        finally:
            os.close(top)
    return FD[0]


def read_req(name, most=262144):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=web_fd())
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused('%s is not a file' % name)
        data = os.read(fd, most + 1)
    finally:
        os.close(fd)
    if len(data) > most:
        raise Refused('the request is far bigger than any address needs')
    return data


def write_here(name, text):
    d = web_fd()
    tmp = '.%s.%d' % (name, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=d)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
        try:
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam('acme').gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)


def write_root(path, text, mode):
    """A file of root's, replaced whole."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=folder)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), mode)        # the file itself, never a link (1.0.205)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def pg_file_put(path, text, mode, uid=None, gid=None):
    """A file in a folder of PostgreSQL's, replaced whole (1.0.149): written
    to a new file of an unguessable name, its mode and owner set on the open
    file, then renamed over - never a name followed, which whoever runs as
    postgres could have made a link to a file of root's."""
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=folder)
    try:
        os.fchmod(fd, mode)
        if uid is not None:
            os.fchown(fd, uid, gid if gid is not None else -1)
        with os.fdopen(fd, 'w') as f:
            fd = None
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def pg_file_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused('%s is not a plain file' % path)
        return f.read()


def pg_path_checked(path, folder=False):
    """A path PostgreSQL said (SHOW data_directory / hba_file) taken only where it is its own
    (1.0.44): absolute, no link, it and its folder owned by root or postgres and written by no one
    else - a server answering on postgres's socket could otherwise point root at any file."""
    path = str(path or '')
    if not path.startswith('/') or '\x00' in path:
        raise Refused('PostgreSQL named no absolute path (%s)' % path[:100])
    try:
        import pwd
        pg_uid = pwd.getpwnam('postgres').pw_uid
    except (KeyError, ImportError):
        pg_uid = None
    ok_uid = {0} | ({pg_uid} if pg_uid is not None else set())
    # A data folder moved to another disk behind a link (main -> /srv/pg/main) is common:
    # the link root's or postgres's own, then what it points at checked as the path (1.0.44).
    try:
        lst = os.lstat(path)
    except OSError:
        raise Refused('%s is not there' % path[:100])
    if stat.S_ISLNK(lst.st_mode):
        if lst.st_uid not in ok_uid:
            raise Refused('%s is a link of another account - not touched' % path[:100])
        real = os.path.realpath(path)
        # postgres's own link only to what is postgres's own: not to a file of root's.
        if lst.st_uid != 0:
            try:
                if pg_uid is None or os.lstat(real).st_uid != pg_uid:
                    raise Refused('%s is a link of postgres to what is not its own - not '
                                  'touched' % path[:100])
            except OSError:
                raise Refused('%s is not there' % real[:100])
        path = real
    for p, want_dir in ((path, folder), (os.path.dirname(path), True)):
        try:
            st = os.lstat(p)
        except OSError:
            raise Refused('%s is not there' % p[:100])
        if stat.S_ISLNK(st.st_mode) or (stat.S_ISDIR(st.st_mode) != want_dir) or \
                st.st_uid not in ok_uid or st.st_mode & 0o002:
            raise Refused('%s is not PostgreSQL\'s own (a link, or owned or written by another '
                          'account) - not touched' % p[:100])
    return path


def pg_file_copy(src, dst):
    """src copied to dst the same way; its owner and mode kept."""
    st = os.lstat(src)
    pg_file_put(dst, pg_file_read(src), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)


# ---- what a request may hold ---------------------------------------------------------
NAME_RE = re.compile(r'^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)'
                     r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z')
IFACE_RE = re.compile(r'^(?!\.+\Z)[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}\Z')   # not . or .., not -x (otp 1.0.234)
NODE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z')
CERT_RE = re.compile(r'^(\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----)+\s*\Z')
KEY_RE = re.compile(r'^\s*-----BEGIN (RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s:,-]+'
                    r'-----END (RSA |EC )?PRIVATE KEY-----\s*$')
PROTOCOLS = ('TLSv1.2', 'TLSv1.3')
DH_CHOICES = ('none', 'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'gen2048', 'gen3072', 'gen4096')


def openssl(args, what, data=None):
    got = subprocess.run(['openssl'] + args, capture_output=True, text=True, input=data)
    if got.returncode != 0:
        raise Refused('%s: %s' % (what, (got.stderr or got.stdout).strip().splitlines()[-1:]
                                  or ['openssl said no']))
    return got.stdout


def pem_set(cert, key, chain='', root=''):
    """A certificate, its key, the certificates between it and the root, and
    the root - each read by openssl, the key the certificate's own."""
    cert, key = str(cert or '').strip(), str(key or '').strip()
    chain, root = str(chain or '').strip(), str(root or '').strip()
    if not cert and not key:
        return None
    if not cert or not key:
        raise Refused('a certificate needs its key, and a key its certificate')
    for what, text in (('the certificate', cert), ('the chain', chain), ('the root', root)):
        if text and not CERT_RE.match(text):
            raise Refused('%s is not PEM (-----BEGIN CERTIFICATE-----)' % what)
    if not KEY_RE.match(key):
        raise Refused('the key is not a PEM private key without a passphrase')
    with tempfile.TemporaryDirectory(prefix='acme-web-') as t:
        cf, kf = os.path.join(t, 'c.pem'), os.path.join(t, 'k.pem')
        with open(cf, 'w') as f:
            f.write(cert + '\n')
        with open(kf, 'w') as f:
            f.write(key + '\n')
        os.chmod(kf, 0o600)
        a = openssl(['x509', '-in', cf, '-noout', '-pubkey'], 'the certificate')
        b = openssl(['pkey', '-in', kf, '-pubout'], 'the key')
        if a.strip() != b.strip():
            raise Refused('the key is not the one of this certificate')
    return {'cert': cert + '\n', 'key': key + '\n', 'chain': (chain + '\n') if chain else '',
            'root': (root + '\n') if root else ''}


def tls_checked(t, name):
    if t is None:
        return None
    if not isinstance(t, dict):
        raise Refused('the TLS of %s is not an object' % name)
    out = {'pem': pem_set(t.get('cert'), t.get('key'), t.get('chain'), t.get('root'))}
    alt = t.get('alt')
    if alt and out['pem']:
        # Its second certificate (1.0.196): ECDSA beside RSA, the same names.
        if not isinstance(alt, dict):
            raise Refused('the second certificate of %s is not an object' % name)
        out['pem']['alt'] = pem_set(alt.get('cert'), alt.get('key'), alt.get('chain'), '')
    prot = t.get('protocols') or list(PROTOCOLS)
    if not isinstance(prot, list) or not prot or any(p not in PROTOCOLS for p in prot):
        raise Refused('the protocols are TLSv1.2 and/or TLSv1.3')
    out['protocols'] = [p for p in PROTOCOLS if p in prot]
    ciphers = str(t.get('ciphers') or '').strip()
    if ciphers:
        if not re.match(r'^(?!-)[A-Za-z0-9_+!@=:.-]{1,2000}\Z', ciphers):
            raise Refused('the ciphers are an OpenSSL cipher list: letters, digits, : + ! - =')
        openssl(['ciphers', ciphers], 'OpenSSL does not know that cipher list')
    out['ciphers'] = ciphers
    out['prefer'] = bool(t.get('prefer'))
    dh = str(t.get('dh') or 'none')
    if dh not in DH_CHOICES:
        raise Refused('the DH parameters are one of %s' % ', '.join(DH_CHOICES))
    out['dh'] = dh
    out['hsts'] = int(t.get('hsts') or 0)
    if not 0 <= out['hsts'] <= 63072000:
        raise Refused('HSTS is 0 to 63072000 seconds')
    return out


def checked(r):
    """The request, every value in the one shape it may have."""
    if not isinstance(r, dict):
        raise Refused('the request is not an object')
    out = {'id': re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:32],
           'hash': re.sub(r'[^0-9a-f]', '', str(r.get('hash') or ''))[:64]}
    node = str(r.get('node') or '')
    if not NODE_RE.match(node):
        raise Refused('the node\'s name is letters, digits, dots, dashes')
    out['node'] = node
    tls = r.get('tls') or {}
    out['tls_node'] = tls_checked(tls.get('node'), 'this node')
    out['tls_vip'] = tls_checked(tls.get('vip'), 'the web address')
    fw = r.get('fw')
    if isinstance(fw, dict):
        rules = fw.get('rules') or []
        # 2000 (1.0.59): a RADIUS rule per client and family came to 400 with
        # 200 clients, and the whole request - certificate, web address and
        # all - was refused for it.
        if not isinstance(rules, list) or len(rules) > 2000:
            raise Refused('the firewall rules are a list, 2000 at most')
        out['fw'] = {'on': bool(fw.get('on')), 'rules': [fw_rule_checked(x) for x in rules]}
    else:
        out['fw'] = None
    out['access'] = access_checked(r.get('access'))
    rp = r.get('realip')
    if rp is None:
        out['realip'] = None                # never asked: nginx's real_ip left alone (otp 1.0.237)
    else:
        nets, head, rec = realip_checked(rp)
        out['realip'] = {'from': nets, 'header': head, 'recursive': rec}
    # The balancer's own address for the enrolment pages (otp 1.0.239): asked only once the
    # sign-in by the balancer was switched on - None leaves nginx as it is.
    sp = r.get('sso_peer')
    out['sso_peer'] = None if sp is None else bool(sp)
    out['pki'] = bool(r.get('pki'))
    names = r.get('acme')
    if names is None:
        out['acme'] = None
    else:
        if not isinstance(names, list) or len(names) > 10 or \
                not all(isinstance(n, str) and re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', n)
                        for n in names):
            raise Refused('the names of the ACME certificates are DNS names, 10 at most')
        out['acme'] = names
    v = r.get('vip') or {}
    out['vip'] = vip = {'on': bool(v.get('on'))}
    if not vip['on']:
        return out
    try:
        net = plain(v.get('address'), 'interface')
    except ValueError:
        raise Refused('the web address is not an address with its prefix (192.0.2.10/24)')
    if net.ip.is_loopback or net.ip.is_multicast or net.ip.is_unspecified:
        raise Refused('%s cannot be the web address' % net.ip)
    vip['address'], vip['family'] = str(net), net.version
    for k in ('own', 'peer'):
        try:
            a = plain(v.get(k), 'address')
        except ValueError:
            raise Refused('%s is not an address: %r' % (k, str(v.get(k))[:60]))
        if a.version != net.version:
            raise Refused('the nodes\' addresses and the web address are not of one kind '
                          '(IPv4 / IPv6)')
        vip[k] = str(a)
    if vip['own'] == vip['peer'] or str(net.ip) in (vip['own'], vip['peer']):
        raise Refused('the web address must be a third address, not one of the nodes\'')
    iface = str(v.get('iface') or '').strip()
    if iface and not IFACE_RE.match(iface):
        raise Refused('%r is not the name of a network interface' % iface[:20])
    vip['iface'] = iface
    # An IPv6 address of the web address beside the IPv4 one (1.0.119): moved
    # with it by the same VRRP instance; the nodes still speak VRRP over IPv4.
    vip['address6'] = ''
    if v.get('address6'):
        try:
            n6 = plain(v.get('address6'), 'interface')
        except ValueError:
            raise Refused('the IPv6 web address is an address with its prefix (2001:db8::10/64)')
        if n6.version != 6 or n6.ip.is_link_local or n6.ip.is_loopback:
            raise Refused('the IPv6 web address is a global IPv6 address')
        vip['address6'] = str(n6)
    try:
        vip['vrid'] = int(v.get('vrid'))
    except (TypeError, ValueError):
        raise Refused('the VRRP id is a number')
    if not 1 <= vip['vrid'] <= 255:
        raise Refused('the VRRP id is 1 to 255')
    if not re.match(r'^[A-Za-z0-9]{8}\Z', str(v.get('auth') or '')):
        raise Refused('the VRRP password is eight letters and digits')
    vip['auth'] = str(v['auth'])
    fqdn = str(v.get('fqdn') or '').strip().lower().rstrip('.')
    if fqdn and not NAME_RE.match(fqdn):
        raise Refused('%r is not a host name' % fqdn[:80])
    vip['fqdn'] = fqdn
    if out['tls_vip'] and out['tls_vip']['pem'] and not fqdn:
        raise Refused('a certificate of its own needs the name it is for')
    return out


# ---- the parts of the machine it changes ---------------------------------------------
def run(cmd, what, ok=(0,)):
    got = subprocess.run(cmd, capture_output=True, text=True)
    if got.returncode not in ok:
        raise Refused('%s: %s' % (what, (got.stderr or got.stdout).strip()[-300:] or
                                  'ended with %d' % got.returncode))
    return got.stdout


def iface_of(address, near=''):
    """The interface that holds `address` here - or, when none does (the
    node's address just changed, 1.0.120), the one with an address in the
    network of `near` (the web address with its prefix)."""
    out = run(['ip', '-o', 'addr', 'show'], 'ip addr')
    rows = [line.split() for line in out.splitlines()]
    for f in rows:
        if len(f) >= 4 and f[3].split('/')[0] == address:
            return f[1].split('@')[0]
    try:
        net = ipaddress.ip_interface(near).network if near else None
    except ValueError:
        net = None
    if net is not None:
        for f in rows:
            if len(f) < 4 or f[2] not in ('inet', 'inet6') or f[1] == 'lo':
                continue
            try:
                one = ipaddress.ip_interface(f[3])
            except ValueError:
                continue
            if one.ip in net and str(one.ip) != str(ipaddress.ip_interface(near).ip):
                return f[1].split('@')[0]
    raise Refused('no interface here holds %s - is it this node\'s address?' % address)


def keepalived_installed():
    if shutil.which('keepalived'):
        return 'there'
    if NO_SERVICES:
        raise Refused('keepalived is not installed')
    if shutil.which('dnf'):
        run(['dnf', '-y', 'install', 'keepalived'], 'dnf install keepalived')
    elif shutil.which('apt-get'):
        run(['apt-get', 'install', '-y', 'keepalived'], 'apt-get install keepalived')
    else:
        raise Refused('install keepalived on this machine, then turn the address on again')
    return 'installed now'


def ka_ours():
    try:
        with open(KA_CONF) as f:
            head = f.read(len(MARK) + 10)
    except FileNotFoundError:
        return None                                     # nobody's
    return head.startswith(MARK)


def ka_conf(node, v):
    lines = [
        MARK,
        '# The web address of the cluster: %s on one node at a time.' % v['address'],
        '# RADIUS does not use it - both nodes answer RADIUS on their own addresses.',
        'global_defs {',
        '    router_id acme_%s' % re.sub(r'[^A-Za-z0-9_]', '_', node),
        '    enable_script_security',
        '    script_user acme',
        '    vrrp_garp_master_refresh 60',
        '}',
        '',
        '# May this node hold it? acme answering, not in maintenance, not being upgraded.',
        'vrrp_script acme_ok {',
        '    script "%s ok"' % CHECK,
        '    interval 2',
        '    timeout 3',
        '    fall 2',
        '    rise 2',
        '}',
        '',
        '# Is it the node the address is meant to be on? (moved on the pages)',
        'vrrp_script acme_prefer {',
        '    script "%s prefer"' % CHECK,
        '    interval 2',
        '    timeout 3',
        '    weight 50',
        '    fall 1',
        '    rise 1',
        '}',
        '',
        'vrrp_instance acme_web {',
        '    state BACKUP',
        '    interface %s' % v['iface'],
        '    virtual_router_id %d' % v['vrid'],
        '    priority 100',
        '    advert_int 1',
        '    preempt_delay 5',
        '    unicast_src_ip %s' % v['own'],
        '    unicast_peer {',
        '        %s' % v['peer'],
        '    }',
    ]
    if v['family'] == 4:
        lines += ['    authentication {', '        auth_type PASS',
                  '        auth_pass %s' % v['auth'], '    }']
    lines += [
        '    virtual_ipaddress {',
        '        %s dev %s' % (v['address'], v['iface']),
        '    }',
    ]
    if v.get('address6'):
        # Of the other family than the VRRP packets: excluded from them,
        # moved with the instance all the same.
        lines += ['    virtual_ipaddress_excluded {',
                  '        %s dev %s' % (v['address6'], v['iface']),
                  '    }']
    lines += [
        '    track_script {',
        '        acme_ok',
        '        acme_prefer',
        '    }',
        '    notify "%s notify"' % CHECK,
        '}',
        '',
    ]
    return '\n'.join(lines)


def firewall(peer, family, on):
    if NO_SERVICES or not shutil.which('firewall-cmd'):
        return ''
    if subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode != 0:
        return 'firewalld is not running: let VRRP (IP protocol 112) from %s in yourself' % peer
    rule = 'rule family="%s" source address="%s" protocol value="vrrp" accept' % (
        'ipv6' if family == 6 else 'ipv4', peer)
    got = subprocess.run(['firewall-cmd', '--permanent',
                          ('--add-rich-rule=' if on else '--remove-rich-rule=') + rule],
                         capture_output=True, text=True)
    rl = subprocess.run(['firewall-cmd', '--reload'], capture_output=True, text=True)
    # Said when it did not work (1.0.57): VRRP not let in is both nodes
    # holding the address.
    if on and (got.returncode not in (0,) and 'ALREADY_ENABLED' not in (got.stderr or '')
               or rl.returncode != 0):
        return 'firewalld did NOT let VRRP from %s in: %s' % (
            peer, ((got.stderr or rl.stderr or '').strip().splitlines() or ['?'])[-1][:200])
    return 'firewalld: VRRP from %s %s' % (peer, 'let in' if on else 'no longer let in')


REALIP_BEGIN = '    # ACME-REALIP-BEGIN - behind a load balancer or WAF, as set on the pages\n'
REALIP_END = '    # ACME-REALIP-END\n'
HEADER_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]{0,63}\Z')


def realip_checked(rp):
    """The balancers and the header as the daemon asked - checked again here: they go into
    nginx's configuration as they are."""
    if not isinstance(rp, dict):
        raise Refused('realip: not an object')
    nets = []
    for w in (rp.get('from') or [])[:64]:
        try:
            # plain() (1.0.45): ip_network keeps an IPv6 scope id with any character in it -
            # a newline and nginx's own directives into acme.conf, as root.
            nets.append(str(plain(str(w), 'network')))
        except ValueError:
            raise Refused('realip: %r is not an address or a network' % str(w)[:60])
    head = str(rp.get('header') or 'X-Forwarded-For')
    if nets and (not HEADER_RE.match(head) or head.lower() in ('host', 'cookie', 'authorization')):
        raise Refused('realip: %r is not the name of a header' % head[:60])
    return nets, head, bool(rp.get('recursive'))


def realip_into(main, rp):
    """acme's own real_ip lines in the HTTPS server of this node (the VIP address's server is
    made from it): put in, changed or taken out. On, they take the place of what acme
    --trusted-proxy wrote; off, only acme's own go - nothing else of nginx is touched (otp
    1.0.237)."""
    nets, head, rec = realip_checked(rp)
    where = server_block(main)
    if not where:
        raise Refused('no HTTPS server { } was found in %s' % NGINX_MAIN)
    block = main[where[0]:where[1]]
    new = re.sub(r'    # ACME-REALIP-BEGIN.*?# ACME-REALIP-END\n', '', block, flags=re.S)
    if nets:
        new = re.sub(r'    # REALIP-BEGIN.*?# REALIP-END\n', '', new, flags=re.S)
        lines = (REALIP_BEGIN + ''.join('    set_real_ip_from %s;\n' % n for n in nets) +
                 '    real_ip_header %s;\n' % head +
                 '    real_ip_recursive %s;\n' % ('on' if rec else 'off') + REALIP_END)
        head_end = new.index('{') + 1
        nl = new.find('\n', head_end)
        cut = nl + 1 if nl >= 0 else head_end
        new = new[:cut] + lines + new[cut:]
    return main[:where[0]] + new + main[where[1]:]


SSO_PEER_MARK = '# ACME-SSO-PEER'


def sso_peer_into(main, on):
    """The address of the machine the request really came from - the balancer's, not the
    client's from X-Forwarded-For - passed to the enrolment pages as ACME_PEER, so that only the
    balancers named can sign people in (otp 1.0.239). In `location = /` of this node's HTTPS
    server (the VIP address's server is made from it); off, only that line goes."""
    where = server_block(main)
    if not where:
        raise Refused('no HTTPS server { } was found in %s' % NGINX_MAIN)
    block = main[where[0]:where[1]]
    new = re.sub(r'(?m)^[ \t]*fastcgi_param[ \t]+ACME_PEER[^\n]*%s[^\n]*\n'
                 % re.escape(SSO_PEER_MARK), '', block)
    if on:
        m = re.search(r'(?m)^([ \t]*)location[ \t]*=[ \t]*/[ \t]*\{[^\n]*\n', new)
        if not m:
            raise Refused('no location = / { } (the enrolment pages) in the HTTPS server of %s'
                          % NGINX_MAIN)
        pad = m.group(1) + '    '
        new = new[:m.end()] + ('%sfastcgi_param  ACME_PEER $realip_remote_addr;   %s - the '
                               'balancer that signs people in\n' % (pad, SSO_PEER_MARK)) + \
            new[m.end():]
    return main[:where[0]] + new + main[where[1]:]


def server_block(text):
    """(start, end) of the HTTPS server { } of an nginx file."""
    i = 0
    while True:
        m = re.search(r'(?m)^[ \t]*server[ \t]*\{', text[i:])
        if not m:
            return None
        start = i + m.start()
        depth, j = 0, i + m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[start:j + 1]
        if re.search(r'(?m)^\s*listen\s+[^;]*443[^;]*ssl', block) or \
                re.search(r'(?m)^\s*ssl_certificate\s', block):
            return start, j + 1
        i = j + 1


def set_directive(block, name, value):
    """`name value;` in a server { } - replaced where it is, put in after
    server_name where it is not, taken out for None. Only the server's own
    lines: a location { } inside is left alone."""
    lines = block.split('\n')
    depth, at, insert_at = 0, [], None
    for n, line in enumerate(lines):
        if depth == 1 and re.match(r'^\s*%s\s' % re.escape(name), line):
            at.append(n)
        if depth == 1 and insert_at is None and re.match(r'^\s*server_name\s', line):
            insert_at = n + 1
        depth += line.count('{') - line.count('}')
    if value is None:
        for n in reversed(at):
            del lines[n]
        return '\n'.join(lines)
    # Several of one name (1.0.196: two certificates, RSA and ECDSA) - a list.
    values = value if isinstance(value, (list, tuple)) else [value]
    texts = ['    %-25s %s;' % (name, v) for v in values]
    if at:
        for n in reversed(at[1:]):
            del lines[n]
        lines[at[0]:at[0] + 1] = texts
    else:
        pos = insert_at if insert_at is not None else 1
        lines[pos:pos] = texts
    return '\n'.join(lines)


CIPHERS_DEFAULT = ('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
                   'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                   'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305')


# How it is going, for the pages (1.0.50): the step, how many there are,
# what is being done, and - for the long one, making DH parameters - when it
# began and about how long it takes.
PROGRESS = {'step': 0, 'total': 6, 'id': ''}
DH_READY = {}
DH_EXPECT_S = {'gen2048': 15, 'gen3072': 120, 'gen4096': 600}


def progress(words, step=None, expect=None):
    if step is not None:
        PROGRESS['step'] = step
    try:
        write_here('progress.json', json.dumps({
            'id': PROGRESS['id'], 'step': PROGRESS['step'], 'total': PROGRESS['total'],
            'words': words, 'at': time.time(), 'expect_s': expect}))
    except OSError:
        pass


def dh_file(choice, path, had):
    """The DH parameters for `choice` in `path`: a group of RFC 7919, or made
    here (which takes a while - 4096 bits minutes). Made ones are made once."""
    if choice == 'none':
        return None
    if choice == had and os.path.exists(path):
        return path
    if choice.startswith('ffdhe'):
        pem = openssl(['genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt',
                       'group:%s' % choice], 'the DH group %s' % choice)
    else:
        progress('making DH parameters of %s bits' % choice[3:], 2, DH_EXPECT_S.get(choice))
        pem = openssl(['dhparam', choice[3:]], 'making DH parameters of %s bits' % choice[3:])
    write_root(path, pem, 0o644)
    return path


TLS_FILES_NEW = [False]           # a certificate or key file of nginx's changed (1.0.205)


def _tls_put(path, text, mode):
    """A certificate or key file written; noted when it is not what was there."""
    try:
        with open(path, 'rb') as f:
            same = f.read() == text.encode('utf-8')
    except OSError:
        same = False
    write_root(path, text, mode)
    if not same:
        TLS_FILES_NEW[0] = True


def tls_into(block, t, files, had_dh):
    """A server { } with the TLS of `t`: its files written, its lines set.
    Returns (block, words, dh made)."""
    said = []
    progress('writing the certificate and the TLS settings', 3)
    if t['pem']:
        full = t['pem']['cert'] + t['pem']['chain']
        _tls_put(files['cert'], full, 0o644)
        _tls_put(files['key'], t['pem']['key'], 0o600)
        alt = t['pem'].get('alt')
        if alt:
            # RSA first, the default; ECDSA to the clients that take it (1.0.196).
            _tls_put(files['cert2'], alt['cert'] + alt['chain'], 0o644)
            _tls_put(files['key2'], alt['key'], 0o600)
            block = set_directive(block, 'ssl_certificate', [files['cert'], files['cert2']])
            block = set_directive(block, 'ssl_certificate_key', [files['key'], files['key2']])
        else:
            block = set_directive(block, 'ssl_certificate', files['cert'])
            block = set_directive(block, 'ssl_certificate_key', files['key'])
        if t['pem']['root']:
            _tls_put(files['root'], t['pem']['root'] + t['pem']['chain'], 0o644)
            block = set_directive(block, 'ssl_trusted_certificate', files['root'])
        else:
            block = set_directive(block, 'ssl_trusted_certificate', None)
        subj = openssl(['x509', '-noout', '-subject', '-enddate'], 'the certificate',
                       t['pem']['cert']).strip().replace('\n', ', ')
        said.append('certificate: %s' % subj)
    block = set_directive(block, 'ssl_protocols', ' '.join(t['protocols']))
    block = set_directive(block, 'ssl_ciphers', t['ciphers'] or CIPHERS_DEFAULT)
    block = set_directive(block, 'ssl_prefer_server_ciphers', 'on' if t['prefer'] else 'off')
    dh = DH_READY.get(files['dh'], 'none?')
    if dh == 'none?':
        dh = dh_file(t['dh'], files['dh'], had_dh)
    block = set_directive(block, 'ssl_dhparam', dh)
    if t['hsts']:
        block = set_directive(block, 'add_header Strict-Transport-Security',
                              '"max-age=%d" always' % t['hsts'])
    else:
        block = set_directive(block, 'add_header Strict-Transport-Security', None)
    said.append('%s; %s; DH %s%s' % (' '.join(t['protocols']),
                                     'ciphers as set' if t['ciphers'] else 'the usual ciphers',
                                     t['dh'], '; HSTS %d s' % t['hsts'] if t['hsts'] else ''))
    return block, said, t['dh']


NODE_FILES = {'cert': os.path.join(CERT_DIR, 'acme.pem'), 'key': os.path.join(CERT_DIR, 'acme.key'),
              'cert2': os.path.join(CERT_DIR, 'acme-ecdsa.pem'), 'key2': os.path.join(CERT_DIR, 'acme-ecdsa.key'),
              'root': os.path.join(CERT_DIR, 'acme-ca.pem'),
              'dh': os.path.join(CERT_DIR, 'acme-dh.pem')}
VIP_FILES = {'cert': os.path.join(CERT_DIR, 'acme-vip.pem'),
             'key': os.path.join(CERT_DIR, 'acme-vip.key'),
             'cert2': os.path.join(CERT_DIR, 'acme-vip-ecdsa.pem'),
             'key2': os.path.join(CERT_DIR, 'acme-vip-ecdsa.key'),
             'root': os.path.join(CERT_DIR, 'acme-vip-ca.pem'),
             'dh': os.path.join(CERT_DIR, 'acme-vip-dh.pem')}


def snapshot(paths):
    got = {}
    for p in paths:
        try:
            with open(p, 'rb') as f:
                got[p] = (f.read(), os.stat(p).st_mode & 0o777)
        except FileNotFoundError:
            got[p] = None
    return got


def put_back(snap):
    for p, was in snap.items():
        if was is None:
            try:
                os.unlink(p)
            except OSError:
                pass
        else:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
            with os.fdopen(fd, 'wb') as f:
                f.write(was[0])
                f.flush()
                os.fchmod(f.fileno(), was[1])     # the file itself (1.0.205)
            os.replace(tmp, p)
            # Its SELinux label too, not the folder's (1.0.57).
            if shutil.which('restorecon'):
                subprocess.run(['restorecon', p], capture_output=True)


SYSCTL_FILE = '/etc/sysctl.d/90-acme-vip.conf'


def nonlocal_bind(family, also=None):
    """nginx may listen on the web address on the node that does not hold
    it - so it answers at once when the address comes over."""
    keys = []
    for fam in (family, also):
        if fam:
            k = 'net.ipv6.ip_nonlocal_bind' if fam == 6 else 'net.ipv4.ip_nonlocal_bind'
            if k not in keys:
                keys.append(k)
    want = '%s\n%s\n' % (MARK, '\n'.join('%s = 1' % k for k in keys))
    try:
        with open(SYSCTL_FILE) as f:
            if f.read() == want:
                return ''
    except OSError:
        pass
    if NO_SERVICES:
        return ''
    write_root(SYSCTL_FILE, want, 0o644)
    for k in keys:
        subprocess.run(['sysctl', '-w', '%s=1' % k], capture_output=True)
    return 'sysctl: %s = 1 (nginx listens on the web address on both nodes)' % ', '.join(keys)


# ---- who may reach which pages (1.0.52) -----------------------------------------------
# acme.conf has a list of its own for the enrolment pages, the administration
# pages and /healthz, between marks (install.sh writes the first two). The
# pages set them; the cluster's own addresses are always among them.
ACCESS_PAGES = (('portal', 'PORTAL', 'location = / {'), ('admin', 'ADMIN', 'location = /admin/ {'),
                ('health', 'HEALTH', 'location = /healthz {'))


def access_checked(a):
    if not isinstance(a, dict):
        return None
    out = {}
    for k, _m, _l in ACCESS_PAGES:
        one = a.get(k)
        if not isinstance(one, dict):
            raise Refused('who may reach the %s pages is not given' % k)
        nets = []
        for x in (one.get('from') or [])[:400]:     # the cluster's on top of 200 (1.0.59)
            try:
                nets.append(str(plain(x, 'network')))
            except ValueError:
                raise Refused('%r is not an address or a network' % str(x)[:60])
        if not one.get('any') and not nets:
            raise Refused('the %s pages would be for nobody: give a network or everybody' % k)
        out[k] = {'any': bool(one.get('any')), 'from': list(dict.fromkeys(nets))}
    return out


def access_lines(one, pad):
    if one['any']:
        return pad + 'allow all;                    # everybody (Settings - Firewall)'
    return '\n'.join('%sallow %s;' % (pad, n) for n in one['from'])


def access_into(text, access):
    """acme.conf with the three lists as asked."""
    for k, mark, loc in ACCESS_PAGES:
        rx = re.compile(r'([ \t]*)# %s-ALLOW-BEGIN\n(?:.*?\n)?([ \t]*)# %s-ALLOW-END' % (mark, mark),
                        re.S)
        if not rx.search(text):
            # Not there yet (the /healthz one, or a file from before): put in,
            # with the only other two lines a list needs, in every HTTPS server
            # that has this location.
            i = 0
            while True:
                i = text.find(loc, i)
                if i < 0:
                    break
                j = text.index('\n', i) + 1
                pad = re.match(r'[ \t]*', text[text.rfind('\n', 0, i) + 1:]).group(0) + '    '
                text = (text[:j] + '%s# %s-ALLOW-BEGIN\n%s# %s-ALLOW-END\n%sallow 127.0.0.1;\n'
                        '%sallow ::1;\n%sdeny  all;\n' % (pad, mark, pad, mark, pad, pad, pad) +
                        text[j:])
                i = j
        text = rx.sub(lambda m: '%s# %s-ALLOW-BEGIN\n%s\n%s# %s-ALLOW-END' % (
            m.group(1), mark, access_lines(access[k], m.group(1)), m.group(2), mark), text)
    return text


def access_now():
    """What acme.conf says now, for the pages."""
    try:
        with open(NGINX_MAIN) as f:
            text = f.read()
    except OSError:
        return {}
    out = {}
    for k, mark, _l in ACCESS_PAGES:
        m = re.search(r'# %s-ALLOW-BEGIN\n(.*?)\n[ \t]*# %s-ALLOW-END' % (mark, mark), text, re.S)
        if not m:
            out[k] = {'any': True, 'from': [], 'marked': False}
            continue
        nets = re.findall(r'(?m)^\s*allow\s+([^;\s]+);', m.group(1))
        out[k] = {'any': 'all' in nets, 'from': [n for n in nets if n != 'all'], 'marked': True}
    return out


ACME_LOCATION = '''    # A certificate by ACME (1.0.169): the CA's HTTP-01 challenge answered on
    # port 80 by acme.php - the answer is in acme's database, so whichever node
    # the CA reaches gives it. Everything else goes to HTTPS.
    location ^~ /.well-known/acme-challenge/ {
        limit_req     zone=acme_all burst=20 nodelay;
        fastcgi_pass  unix:/run/php-fpm/acme.sock;
        fastcgi_param SCRIPT_FILENAME /var/www/acme/acme.php;
        include       fastcgi_params;
        fastcgi_read_timeout 10s;
    }
''' + '''    # A commercial CA's file-based domain validation (DigiCert http-token,
    # Sectigo FILE), answered by acme.php in the same way.
    location ^~ /.well-known/pki-validation/ {
        limit_req     zone=acme_all burst=20 nodelay;
        fastcgi_pass  unix:/run/php-fpm/acme.sock;
        fastcgi_param SCRIPT_FILENAME /var/www/acme/acme.php;
        include       fastcgi_params;
        fastcgi_read_timeout 10s;
    }
    location / {
        return 301 https://$host$request_uri;
    }'''
PKI_VALIDATION_LOCATION = ACME_LOCATION.split('    location / {')[0].split(
    '    # A commercial CA')[1]
PKI_VALIDATION_LOCATION = '    # A commercial CA' + PKI_VALIDATION_LOCATION


def http_block(text):
    """(start, end) of the port-80 server { } of an nginx file."""
    for m in re.finditer(r'(?m)^[ \t]*server[ \t]*\{', text):
        depth, j = 0, m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[m.start():j + 1]
        if re.search(r'(?m)^\s*listen\s+(\[::\]:)?80\b', block) and 'ssl' not in block.split('{', 1)[1][:400]:
            return m.start(), j + 1
    return None


def acme_into(main, names):
    """The port-80 server given the ACME location (1.0.169), and the names
    certificates are ordered for in its server_name - the web address's on
    every node, so the CA reaches acme on whichever node has it."""
    where = http_block(main)
    if not where:
        return main
    block = main[where[0]:where[1]]
    new = block
    if 'acme-challenge' not in new:
        new = re.sub(r'(?m)^[ \t]*return[ \t]+301[ \t]+https://\$host\$request_uri;[ \t]*$',
                     lambda m: ACME_LOCATION, new, count=1)
    elif 'pki-validation' not in new:
        # an older ACME location (before the DCV files): theirs put beside it
        m = re.search(r'(?m)^[ \t]*location[ \t]+\^~[ \t]+/\.well-known/acme-challenge/[ \t]*\{', new)
        if m:
            new = new[:m.start()] + PKI_VALIDATION_LOCATION + new[m.start():]
    m = re.search(r'(?m)^(\s*server_name\s+)([^;#]*);', new)
    if m and names:
        have = m.group(2).split()
        base = [x for x in have if not x.startswith('acme-acme:')]
        want = base + [n for n in names if n not in base]
        if want != have:
            new = new[:m.start()] + m.group(1) + ' '.join(want) + ';' + new[m.end():]
    return main[:where[0]] + new + main[where[1]:] if new != block else main


PKI_MARK = 'location ^~ /pki/'


def pki_location(pad, sock, tls):
    """/pki/ to pki.php: the CRLs and certificates of acme's own authorities,
    for everybody - on port 80 never sent to HTTPS."""
    lines = ['# The CRLs and certificates of acme\'s own authorities (docs/own-ca.md):',
             '# for everybody, plain HTTP - a CRL fetcher seldom follows a redirect.',
             '# PKI-BEGIN',
             'location = /pki { return 301 /pki/; }',
             PKI_MARK + ' {',
             '    limit_req     zone=acme_all burst=40 nodelay;',
             '    limit_req_status 429;',
             '    fastcgi_pass  %s;' % sock,
             '    fastcgi_param SCRIPT_FILENAME /var/www/acme/pki.php;']
    if tls:
        lines.append('    fastcgi_param HTTPS on;')
    lines += ['    include       fastcgi_params;', '    fastcgi_read_timeout 15s;', '}',
              '# PKI-END']
    return ''.join(pad + ln + '\n' for ln in lines)


def pki_into(main):
    """/pki/ put into the port-80 server (in front of the redirect to HTTPS)
    and into the HTTPS server (in front of /assets/), where it is missing."""
    sockm = re.search(r'fastcgi_pass\s+([^;]+);', main)
    sock = sockm.group(1).strip() if sockm else 'unix:/run/php-fpm/acme.sock'
    zone = re.search(r'limit_req_zone\s+\$binary_remote_addr\s+zone=([A-Za-z0-9_]+):', main)
    where = http_block(main)
    if where:
        block = main[where[0]:where[1]]
        if PKI_MARK not in block:
            m = re.search(r'(?m)^([ \t]*)location[ \t]+/[ \t]*\{', block)
            if m:
                new = block[:m.start()] + pki_location(m.group(1), sock, False) + block[m.start():]
                main = main[:where[0]] + new + main[where[1]:]
    where = server_block(main)
    if where:
        block = main[where[0]:where[1]]
        if PKI_MARK not in block:
            m = re.search(r'(?m)^([ \t]*)location[ \t]+/assets/', block) or \
                re.search(r'(?m)^([ \t]*)location[ \t]+~[ \t]+\\\.php', block)
            if m:
                new = block[:m.start()] + pki_location(m.group(1), sock, True) + '\n' + \
                    block[m.start():]
                main = main[:where[0]] + new + main[where[1]:]
    if zone and zone.group(1) != 'acme_all':
        main = main.replace('limit_req     zone=acme_all burst=40', 'limit_req     zone=%s burst=40'
                            % zone.group(1))
    elif not zone:
        main = re.sub(r'(?m)^[ \t]*limit_req +zone=acme_all burst=40 nodelay;\n[ \t]*'
                      r'limit_req_status 429;\n', '', main)
    return main


def nginx_part(r, last):
    """This node's server and the web address's, with their TLS."""
    said, dh = [], {}
    # DH parameters made first (1.0.50): it can take minutes, and nginx's file
    # is read only after it, so nothing changed in it meanwhile (an upgrade)
    # is written over with an older copy.
    for t, files, which in ((r['tls_node'], NODE_FILES, 'node'),
                            (r['tls_vip'] if r['vip']['on'] else None, VIP_FILES, 'vip')):
        if not t:
            continue
        # The same parameters made for the node serve the web address too
        # (1.0.51): made once, not twice.
        if which == 'vip' and t['dh'].startswith('gen') and r['tls_node'] and \
                r['tls_node']['dh'] == t['dh'] and DH_READY.get(NODE_FILES['dh']) and \
                (last.get('dh') or {}).get('vip') != t['dh']:
            shutil.copyfile(NODE_FILES['dh'], files['dh'])
            os.chmod(files['dh'], 0o644)
            DH_READY[files['dh']] = files['dh']
            continue
        DH_READY[files['dh']] = dh_file(t['dh'], files['dh'], (last.get('dh') or {}).get(which))
    paths = [NGINX_MAIN, NGINX_VIP] + list(NODE_FILES.values()) + list(VIP_FILES.values())
    snap = snapshot(paths)
    changed = False
    TLS_FILES_NEW[0] = False
    try:
        try:
            with open(NGINX_MAIN) as f:
                main = f.read()
        except OSError as e:
            raise Refused('acme\'s nginx file cannot be read (%s): %s' % (NGINX_MAIN, e))
        if r.get('acme') is not None:
            new_main = acme_into(main, r['acme'])
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                said.append('nginx: port 80 answers the ACME CA (%s)' % (', '.join(r['acme']) or
                                                                        'no name yet'))
        if r.get('pki'):
            new_main = pki_into(main)
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                said.append('nginx: /pki/ serves the CRLs of acme\'s own authorities, port 80 '
                            'and 443, for everybody')
        if r.get('access'):
            new_main = access_into(main, r['access'])
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                said.append('nginx: who may reach the enrolment, administration and health '
                            'pages set')
        # Behind a balancer, and signed in by it (otp 1.0.237, 1.0.239). Not put in, said and
        # gone on: a refusal of these refused the whole request - the certificates, the VIP
        # address and the firewall too (the lesson of otp 1.0.242).
        if r.get('realip') is not None:
            try:
                new_main = realip_into(main, r['realip'])
            except Refused as e:
                said.append('nginx: the client\'s address from the load balancer NOT put in: %s' % e)
                new_main = main
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                rp = r['realip']
                said.append('nginx: the client\'s address from %s when it comes from %s'
                            % (rp.get('header'), ', '.join(rp.get('from')))
                            if rp.get('from') else 'nginx: no balancer believed any more')
        if r.get('sso_peer') is not None:
            try:
                new_main = sso_peer_into(main, r['sso_peer'])
            except Refused as e:
                said.append('nginx: the enrolment pages NOT told which machine a request came '
                            'from: %s' % e)
                new_main = main
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
                said.append('nginx: the enrolment pages told which machine a request came from '
                            '(signed in by the load balancer)' if r['sso_peer'] else
                            'nginx: the enrolment pages no longer told which machine a request '
                            'came from')
        where = server_block(main)
        if not where:
            raise Refused('no HTTPS server { } was found in %s' % NGINX_MAIN)
        block = main[where[0]:where[1]]
        if r['tls_node']:
            new, words, dh['node'] = tls_into(block, r['tls_node'], NODE_FILES,
                                              (last.get('dh') or {}).get('node'))
            if new != block:
                write_root(NGINX_MAIN, main[:where[0]] + new + main[where[1]:], 0o644)
                changed = True
            said += ['this node: ' + w for w in words]
            block = new
        vip, tv = r['vip'], r['tls_vip']
        if vip['on'] and tv and tv['pem']:
            vb = re.sub(r'(?m)^(\s*)server_name\s+[^;]*;', r'\1server_name %s;' % vip['fqdn'],
                        block, count=1)
            vb = re.sub(r'\s+default_server\b', '', vb)
            # Its own address as well as its name (1.0.51): a browser that
            # asks for the address itself, or sends no name at all, gets the
            # web address's certificate - not the node's. The address need
            # not be on this node for nginx to listen on it (ip_nonlocal_bind).
            ip = vip['address'].split('/')[0]
            host = '[%s]' % ip if ':' in ip else ip
            vb = re.sub(r'(?m)^(\s*)listen\s+(?:\[[^\]]*\]:|[0-9.]+:)?443\b([^;]*);',
                        r'\1listen %s:443\2;' % host, vb)
            lines, seen = [], set()
            for line in vb.split('\n'):
                k = line.strip()
                if k.startswith('listen ') and k in seen:
                    continue
                seen.add(k)
                lines.append(line)
            vb = '\n'.join(lines)
            if vip.get('address6'):
                ip6 = vip['address6'].split('/')[0]
                vb = re.sub(r'(?m)^(\s*)(listen\s+%s:443\b[^;]*;)' % re.escape(host),
                            lambda m: '%s%s\n%slisten [%s]:443%s;' % (
                                m.group(1), m.group(2), m.group(1), ip6,
                                m.group(2).split(':443', 1)[1].rstrip(';')), vb, count=1)
            said.append(nonlocal_bind(vip['family'], 6 if vip.get('address6') else None))
            vb, words, dh['vip'] = tls_into(vb, tv, VIP_FILES, (last.get('dh') or {}).get('vip'))
            text = ('%s\n# %s - the web address\'s own name and certificate: a copy of the '
                    'HTTPS server of acme.conf,\n# made again whenever either is changed on the '
                    'pages.\n%s\n' % (MARK, vip['fqdn'], vb))
            if snap.get(NGINX_VIP) is None or snap[NGINX_VIP][0].decode() != text:
                write_root(NGINX_VIP, text, 0o644)
                changed = True
            said += ['the web address (%s): ' % vip['fqdn'] + w for w in words]
        elif os.path.exists(NGINX_VIP):
            os.unlink(NGINX_VIP)
            try:
                os.unlink(SYSCTL_FILE)
            except OSError:
                pass
            for p in VIP_FILES.values():
                try:
                    os.unlink(p)
                except OSError:
                    pass
            changed = True
            said.append('nginx: the web address\'s own server taken away (it answers with this '
                        'node\'s certificate)')
        # A certificate renewed changes no line of nginx's (1.0.205): its files
        # alone were written, nginx was not reloaded, and went on giving the
        # old one until it ran out.
        if TLS_FILES_NEW[0]:
            changed = True
        if changed and not NO_SERVICES:
            progress('asking nginx, and reloading it', 4)
            t = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if t.returncode != 0:
                raise Refused('nginx does not take it, so it is as it was: %s'
                              % ((t.stderr or '').strip().splitlines() or ['?'])[-1][:300])
            subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
            said.append('nginx reloaded')
    except BaseException:
        put_back(snap)
        raise
    return said, dh


def vip_part(r, last):
    said = []
    v = r['vip']
    if not v['on']:
        if ka_ours():
            if not NO_SERVICES:
                subprocess.run(['systemctl', 'disable', '--now', 'keepalived'],
                               capture_output=True)
            os.unlink(KA_CONF)
            said.append('keepalived stopped and its file taken away - the web address is on '
                        'no node')
        if last.get('peer'):
            said.append(firewall(last['peer'], int(last.get('family') or 4), False))
        return said, {}
    if ka_ours() is False:
        raise Refused('%s is there and is not acme\'s: keepalived on this machine is used for '
                      'something else. Move that away first.' % KA_CONF)
    progress('keepalived: the web address', 5)
    said.append('keepalived: %s' % keepalived_installed())
    if not v['iface']:
        v['iface'] = iface_of(v['own'], v.get('address') or '')
    elif not os.path.isdir('/sys/class/net/%s' % v['iface']):
        raise Refused('there is no interface %s on this node' % v['iface'])
    if not os.access(CHECK, os.X_OK):
        raise Refused('%s is missing - install.sh --upgrade puts it in' % CHECK)
    snap = snapshot([KA_CONF])
    write_root(KA_CONF, ka_conf(r['node'], v), 0o640)
    if shutil.which('keepalived') and not NO_SERVICES:
        t = subprocess.run(['keepalived', '-t', '-f', KA_CONF], capture_output=True, text=True)
        if t.returncode != 0:
            put_back(snap)
            raise Refused('keepalived does not take the file: %s'
                          % (t.stderr or t.stdout).strip()[-300:])
    said.append('keepalived: %s on %s, VRRP id %d, with %s'
                % (v['address'], v['iface'], v['vrid'], v['peer']))
    if last.get('peer') and last['peer'] != v['peer']:
        firewall(last['peer'], int(last.get('family') or 4), False)
    said.append(firewall(v['peer'], v['family'], True))
    if not NO_SERVICES:
        active = subprocess.run(['systemctl', 'is-active', '--quiet', 'keepalived']).returncode == 0
        subprocess.run(['systemctl', 'enable', 'keepalived'], capture_output=True)
        run(['systemctl', 'reload' if active else 'start', 'keepalived'],
            'systemctl %s keepalived' % ('reload' if active else 'start'))
        said.append('keepalived %s' % ('read its file again' if active else 'started'))
    return said, {'peer': v['peer'], 'family': v['family'], 'iface': v['iface']}


# ---- the local firewall (1.0.52) ----------------------------------------------------
# Everything acme opens is in a chain of its own, ACME-IN, jumped to first from
# INPUT - for IPv4 (iptables) and IPv6 (ip6tables). The rules already on the
# machine are left exactly as they are: acme's chain only adds to them. With
# iptables-services the chain is also written into /etc/sysconfig/iptables
# and ip6tables (between marks of its own, the rest of the file untouched,
# its comments kept), so it is there after a reboot.
FW_CHAIN = 'ACME-IN'
FW_FILES = {4: os.environ.get('ACME_FW_FILE4', '/etc/sysconfig/iptables'),
            6: os.environ.get('ACME_FW_FILE6', '/etc/sysconfig/ip6tables')}
FW_TOOLS = {4: ('iptables', 'iptables-restore', 'iptables-save'),
            6: ('ip6tables', 'ip6tables-restore', 'ip6tables-save')}
FW_PROTOS = ('tcp', 'udp', 'icmp', 'vrrp', 'any')
FW_MARK = '# acme:'


def fw_backend():
    if not NO_SERVICES and shutil.which('firewall-cmd') and \
            subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode == 0:
        return 'firewalld'
    if shutil.which('iptables'):
        return 'iptables'
    return ''


def fw_rule_checked(x):
    if not isinstance(x, dict):
        raise Refused('a firewall rule is not an object')
    fam = int(x.get('family') or 0)
    if fam not in (4, 6):
        raise Refused('a firewall rule is for IPv4 or IPv6')
    proto = str(x.get('proto') or 'any')
    if proto not in FW_PROTOS:
        raise Refused('the protocol is one of %s' % ', '.join(FW_PROTOS))
    port = str(x.get('port') or '').replace(' ', '')
    if port:
        if proto not in ('tcp', 'udp'):
            raise Refused('a port is for TCP or UDP')
        parts = port.split(',')
        # A range counts as two, as iptables counts it; matched whole - $
        # let a newline at the end through (1.0.59).
        if sum(2 if '-' in p else 1 for p in parts) > 15 or \
                not all(re.fullmatch(r'[0-9]{1,5}(-[0-9]{1,5})?', p) for p in parts):
            raise Refused('the ports are numbers or ranges, by commas: 80,443 or 1812-1813')
        for p in parts:
            a, _, b = p.partition('-')
            if not 1 <= int(a) <= 65535 or (b and not int(a) <= int(b) <= 65535):
                raise Refused('%s is not a port or a range of them' % p)
    src = str(x.get('source') or '').strip()
    if src:
        try:
            net = plain(src, 'network')
        except ValueError:
            raise Refused('%r is not an address or a network' % src[:60])
        if net.version != fam:
            raise Refused('%s is not an IPv%d address' % (src, fam))
        src = str(net)
    action = str(x.get('action') or 'accept')
    if action not in ('accept', 'drop', 'reject'):
        raise Refused('a rule accepts, drops or rejects')
    note = re.sub(r'[^A-Za-z0-9 ._:/@()+,-]', '', str(x.get('note') or ''))[:120]
    return {'family': fam, 'proto': proto, 'port': port, 'source': src, 'action': action,
            'note': note}


def fw_args(r):
    a = ['-A', FW_CHAIN]
    if r['source']:
        a += ['-s', r['source']]
    if r['proto'] != 'any':
        proto = 'ipv6-icmp' if (r['proto'] == 'icmp' and r['family'] == 6) else r['proto']
        a += ['-p', proto]
    if r['port']:
        if ',' in r['port']:
            a += ['-m', 'multiport', '--dports', r['port'].replace('-', ':')]
        else:
            a += ['--dport', r['port'].replace('-', ':')]
    a += ['-m', 'comment', '--comment', '"acme: %s"' % (r['note'] or r['proto'])]
    if r['action'] == 'reject':
        a += ['-j', 'REJECT']
    else:
        a += ['-j', r['action'].upper()]
    return ' '.join(a)


def fw_strip(text):
    """A saved ruleset without anything acme put in it."""
    out = []
    for line in text.split('\n'):
        # iptables-save -c puts the counters first: [12:3456] -A INPUT ...
        k = re.sub(r'^\[\d+:\d+\]\s+', '', line.strip())
        if k.startswith(FW_MARK) or re.match(r'^:%s - \[\d+:\d+\]\Z' % FW_CHAIN, k) or \
                k == '-A INPUT -j %s' % FW_CHAIN or k.startswith('-A %s ' % FW_CHAIN):
            continue
        out.append(line)
    return '\n'.join(out)


def fw_into(text, lines, on):
    """acme's chain into a saved ruleset (iptables-services' file), in the
    *filter table: its name, the jump from INPUT first, its rules last."""
    text = fw_strip(text)
    if not on:
        return text
    rows = text.split('\n')
    try:
        start = next(i for i, l in enumerate(rows) if l.strip() == '*filter')
    except StopIteration:
        rows += ['*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]',
                 ':OUTPUT ACCEPT [0:0]', 'COMMIT']
        start = len(rows) - 5
    end = next((i for i in range(start + 1, len(rows)) if rows[i].strip() == 'COMMIT'), None)
    if end is None:
        raise Refused('the saved firewall has a *filter table without COMMIT')
    last_decl = max([i for i in range(start, end) if rows[i].startswith(':')] or [start])
    first_input = next((i for i in range(start, end) if rows[i].startswith('-A INPUT')), end)
    block = ['%s acme opens what its functions need here (Settings - Firewall); changed '
             'only there' % FW_MARK] + lines + ['%s end' % FW_MARK]
    rows = (rows[:last_decl + 1] + [':%s - [0:0]' % FW_CHAIN] +
            rows[last_decl + 1:first_input] +
            ['%s every rule acme makes is in %s' % (FW_MARK, FW_CHAIN), '-A INPUT -j %s' % FW_CHAIN] +
            rows[first_input:end] + block + rows[end:])
    return '\n'.join(rows)


FW_ASK = 'fw.ask'
FW_NOW = 'fwnow.json'


def fw_full(fam):
    """The whole filter table as iptables-save shows it (1.0.67): INPUT,
    ACME-IN and every other chain, counters and comments left out."""
    tool = FW_TOOLS[fam][2]
    if not shutil.which(tool):
        return []
    got = subprocess.run([tool, '-t', 'filter'], capture_output=True, text=True)
    out = []
    for line in got.stdout.split('\n'):
        line = re.sub(r'^\[\d+:\d+\]\s+', '', line.strip())
        if not line or line.startswith('#') or line in ('*filter', 'COMMIT'):
            continue
        out.append(re.sub(r' \[\d+:\d+\]$', '', line))
    return out[:1500]


def drop_ask(name, d):
    """An asking file taken away, whatever the acme account made of it
    (1.0.94): a link (refused by O_NOFOLLOW) or a folder was never removed,
    the path unit started this service again and again until systemd gave
    up - and with it every later TLS, VIP and firewall change."""
    try:
        os.unlink(name, dir_fd=d)
        return
    except FileNotFoundError:
        return
    except OSError:
        pass
    try:
        os.rmdir(name, dir_fd=d)
        return
    except OSError:
        pass
    try:
        os.rename(name, '.refused-%s-%d' % (name, int(time.time())), src_dir_fd=d, dst_dir_fd=d)
    except OSError:
        pass


def fw_read_part(force=False):
    """The firewall as it is now, written for the pages (1.0.67): when they
    ask for it, and after every change made here."""
    d = web_fd()
    if not force:
        try:
            read_req(FW_ASK, 4096)
        except FileNotFoundError:
            return
        except (Refused, OSError):
            pass
        drop_ask(FW_ASK, d)
    backend = fw_backend()
    out = {'at': time.time(), 'backend': backend,
           'full': {4: fw_full(4), 6: fw_full(6)} if backend == 'iptables' else {}}
    if backend == 'firewalld' and shutil.which('firewall-cmd'):
        got = subprocess.run(['firewall-cmd', '--list-all'], capture_output=True, text=True)
        out['full'] = {4: [x.rstrip() for x in got.stdout.split('\n') if x.strip()][:400], 6: []}
    write_here(FW_NOW, json.dumps(out))


def fw_now(fam):
    """What the machine's INPUT holds now, acme's chain apart - shown on the
    pages as what else is in the firewall."""
    tool = FW_TOOLS[fam][2]
    if not shutil.which(tool):
        return []
    got = subprocess.run([tool, '-t', 'filter'], capture_output=True, text=True)
    out = []
    for line in got.stdout.split('\n'):
        if line.startswith(':INPUT ') or (line.startswith('-A INPUT') and
                                           line.strip() != '-A INPUT -j %s' % FW_CHAIN):
            out.append(line.strip())
    return out[:200]


def fw_base(fam):
    """What the chain lets through before anybody's rule (1.0.59): the
    machine's own loopback, the answers to what it asked itself (LDAP, DNS,
    mail, the other node's replication), and on IPv6 the neighbour
    discovery it cannot live without. Ahead of the rules a DROP of somebody's
    shut every one of them out."""
    out = ['-A %s -i lo -m comment --comment "acme: loopback" -j ACCEPT' % FW_CHAIN,
           '-A %s -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment '
           '"acme: answers" -j ACCEPT' % FW_CHAIN]
    if fam == 6:
        out += ['-A %s -p ipv6-icmp -m icmp6 --icmpv6-type %d -m comment --comment '
                '"acme: neighbour discovery" -j ACCEPT' % (FW_CHAIN, t) for t in (133, 134, 135, 136)]
    return out


def fw_said(stderr):
    """What iptables said, without its last line (1.0.59): that is always
    the hint to read its help."""
    lines = [x.strip() for x in (stderr or '').strip().splitlines()
             if x.strip() and not x.strip().startswith('Try `')]
    return '; '.join(lines[-3:]) or '?'


def fw_apply(f, said):
    for fam in (4, 6):
        tool, restore, _save = FW_TOOLS[fam]
        lines = fw_base(fam) + [fw_args(r) for r in f['rules'] if r['family'] == fam]
        if not shutil.which(tool):
            continue
        if f['on']:
            snippet = '*filter\n:%s - [0:0]\n%s\nCOMMIT\n' % (FW_CHAIN, '\n'.join(lines))
            got = subprocess.run([restore, '--noflush'], input=snippet, capture_output=True,
                                 text=True)
            if got.returncode != 0:
                raise Refused('%s does not take the rules: %s' % (restore, fw_said(got.stderr)))
            if subprocess.run([tool, '-C', 'INPUT', '-j', FW_CHAIN],
                              capture_output=True).returncode != 0:
                subprocess.run([tool, '-I', 'INPUT', '1', '-j', FW_CHAIN], capture_output=True)
            said.append('IPv%d: %d rule(s) in %s' % (fam, len(lines), FW_CHAIN))
        else:
            while subprocess.run([tool, '-D', 'INPUT', '-j', FW_CHAIN],
                                 capture_output=True).returncode == 0:
                pass
            subprocess.run([tool, '-F', FW_CHAIN], capture_output=True)
            subprocess.run([tool, '-X', FW_CHAIN], capture_output=True)
        # Kept over a reboot, where iptables-services keeps the rules.
        path = FW_FILES[fam]
        if os.path.exists(path):
            with open(path) as fh:
                old = fh.read()
            new = fw_into(old, lines, f['on'])
            if new != old:
                fd, tmp = tempfile.mkstemp(prefix='.acme-fw-', dir=os.path.dirname(path))
                with os.fdopen(fd, 'w') as fh:
                    fh.write(new if new.endswith('\n') else new + '\n')
                test = subprocess.run([restore, '--test', tmp], capture_output=True, text=True)
                if test.returncode != 0:
                    os.unlink(tmp)
                    raise Refused('%s would not take the file, so it was left as it was: %s' % (
                        restore, fw_said(test.stderr)))
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
                os.replace(tmp, path)
                if shutil.which('restorecon'):
                    subprocess.run(['restorecon', path], capture_output=True)
                said.append('%s: kept over a reboot' % path)
        elif f['on']:
            said.append('IPv%d: not kept over a reboot - %s is not there (dnf install '
                        'iptables-services)' % (fam, path))


def fw_part(f):
    """The firewall as asked: (words, report)."""
    said = []
    backend = fw_backend()
    report = {'backend': backend, 'now': {4: fw_now(4), 6: fw_now(6)} if backend == 'iptables'
              else {}}
    if f is None:
        return said, report
    if backend == 'firewalld':
        if f['on']:
            raise Refused('firewalld manages this machine\'s firewall: acme leaves it to it (what '
                          'to open is in docs/tls-and-vip.md). To manage it here, use iptables '
                          '(dnf install iptables-services; systemctl disable --now firewalld; '
                          'systemctl enable --now iptables ip6tables)')
        return said, report
    if not backend:
        if f['on']:
            raise Refused('there is no iptables on this machine')
        return said, report
    progress('the firewall', 5)
    # As it was, live and in the files, to go back to when anything fails
    # half way (1.0.57) - never a machine left half done.
    was_live, was_file = {}, {}
    for fam in (4, 6):
        if shutil.which(FW_TOOLS[fam][2]):
            was_live[fam] = subprocess.run([FW_TOOLS[fam][2]], capture_output=True,
                                           text=True).stdout
        if os.path.exists(FW_FILES[fam]):
            was_file[fam] = snapshot([FW_FILES[fam]])
    try:
        fw_apply(f, said)
    except BaseException:
        for fam, text in was_live.items():
            if text.strip():
                subprocess.run([FW_TOOLS[fam][1]], input=text, capture_output=True, text=True)
            else:
                # Nothing there before (1.0.59): what was put in is taken out
                # again, not left live under a "failed".
                tool = FW_TOOLS[fam][0]
                while subprocess.run([tool, '-D', 'INPUT', '-j', FW_CHAIN],
                                     capture_output=True).returncode == 0:
                    pass
                subprocess.run([tool, '-F', FW_CHAIN], capture_output=True)
                subprocess.run([tool, '-X', FW_CHAIN], capture_output=True)
        for snap in was_file.values():
            put_back(snap)
        raise
    if not f['on']:
        said.append('the firewall: acme\'s rules taken away; the rest is as it was')
    report['now'] = {4: fw_now(4), 6: fw_now(6)}
    try:
        fw_read_part(force=True)
    except Exception:                                   # noqa: BLE001
        pass
    return said, report


# ---- PostgreSQL's log, for the replication errors on the pages (1.0.52) -------------
# The log is postgres's (0600): the acme account asks for it with pglog.ask,
# root reads only the lines about logical replication and writes them into
# pglog.json, which the acme group may read. Nothing else is taken from it.
PGLOG_GLOBS = ('/var/lib/pgsql/*/data/log/*.log', '/var/lib/pgsql/data/log/*.log',
               '/var/lib/pgsql/*/data/pg_log/*.log', '/var/log/postgresql/*.log')
PGLOG_WORDS = re.compile(r'logical replication|subscription|apply worker|tablesync|'
                         r'publication|replication slot|replication origin|acme_from_|'
                         r'processing remote data|walsender|wal_status', re.I)
PG_LINE = re.compile(r'^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)(?:\.\d+)?\s*([A-Z]{2,5}|[+-]\d\d(?::?\d\d)?)?\b')


def pg_time(stamp, zone):
    """A log line's time with its zone (1.0.59): UTC, or +02 / +0200, kept
    as said; a name it does not know (CEST) read as this machine's own."""
    tm = time.strptime(stamp.replace('T', ' '), '%Y-%m-%d %H:%M:%S')
    zone = (zone or '').strip()
    import calendar
    if zone in ('UTC', 'GMT', 'Z'):
        return float(calendar.timegm(tm))
    m = re.fullmatch(r'([+-])(\d\d):?(\d\d)?', zone)
    if m:
        off = (int(m.group(2)) * 60 + int(m.group(3) or 0)) * 60
        return float(calendar.timegm(tm)) - (off if m.group(1) == '+' else -off)
    return time.mktime(tm)
PG_LEVEL = re.compile(r'\b(ERROR|FATAL|PANIC|WARNING|LOG|DETAIL|CONTEXT|HINT|STATEMENT):\s\s?(.*)$')


def pglog_files(port):
    import glob
    found = []
    if not NO_SERVICES and shutil.which('runuser') and shutil.which('psql'):
        got = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-p', str(int(port)),
                              '-XAtc', "SELECT current_setting('data_directory'), "
                              "pg_current_logfile()"],
                             capture_output=True, text=True, timeout=10, cwd='/')
        parts = (got.stdout or '').strip().split('|')
        if got.returncode == 0 and len(parts) == 2 and parts[1]:
            f = parts[1] if parts[1].startswith('/') else os.path.join(parts[0], parts[1])
            folder = os.path.dirname(f)
            found = [os.path.join(folder, x) for x in os.listdir(folder)
                     if x.endswith('.log')] if os.path.isdir(folder) else [f]
    if not found:
        for g in PGLOG_GLOBS:
            found += glob.glob(g)
    # Plain files of PostgreSQL's own only (1.0.59): root reads them, and
    # a link in a folder anybody writes to could point at anything.
    try:
        import pwd
        pg_uid = pwd.getpwnam('postgres').pw_uid
    except (KeyError, ImportError):
        pg_uid = None
    good = []
    for f in set(found):
        try:
            st = os.lstat(f)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and (pg_uid is None or st.st_uid == pg_uid):
            good.append(f)
    good.sort(key=lambda f: os.lstat(f).st_mtime)
    return good[-3:]


def pg_owner():
    try:
        import pwd
        return pwd.getpwnam('postgres').pw_uid
    except (KeyError, ImportError):
        return None


def pglog_part():
    d = web_fd()
    try:
        raw = read_req(PGLOG_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(PGLOG_ASK, d)
        return
    drop_ask(PGLOG_ASK, d)
    try:
        port = int(json.loads(raw.decode('utf-8')).get('port') or 5432)
    except (ValueError, TypeError, AttributeError):
        port = 5432
    out = {'at': time.time(), 'entries': [], 'file': '', 'said': ''}
    try:
        files = pglog_files(port)
        if not files:
            out['said'] = 'PostgreSQL\'s log was not found (log_destination stderr with ' \
                          'logging_collector on writes it into data/log)'
        entries, cur = [], None
        for path in files:
            out['file'] = path
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
                # What was opened, checked again (1.0.94): the file looked at
                # and the one opened could differ in between.
                fst = os.fstat(f.fileno())
                if not stat.S_ISREG(fst.st_mode) or (pg_owner() is not None and
                                                      fst.st_uid != pg_owner()):
                    continue
                size = fst.st_size
                f.seek(max(0, size - 4 * 1024 * 1024))
                text = f.read().decode('utf-8', 'replace')
            for line in text.split('\n'):
                m = PG_LEVEL.search(line)
                if not m:
                    if cur is not None and line.startswith(('\t', ' ')):
                        cur['text'] += ' ' + line.strip()
                    continue
                level, said = m.group(1), m.group(2).strip()
                if level == 'STATEMENT':
                    continue        # the statement may hold data: never handed on (1.0.57)
                if level in ('DETAIL', 'CONTEXT', 'HINT'):
                    if cur is not None:
                        cur.setdefault('more', []).append('%s: %s' % (level, said[:600]))
                    continue
                if cur is not None:
                    entries.append(cur)
                cur = None
                if level in ('ERROR', 'FATAL', 'PANIC', 'WARNING') or \
                        (level == 'LOG' and PGLOG_WORDS.search(said)):
                    ts = None
                    t = PG_LINE.match(line)
                    if t:
                        try:
                            ts = pg_time(t.group(1), t.group(2))
                        except ValueError:
                            ts = None
                    cur = {'ts': ts, 'level': level, 'text': said[:1000]}
            if cur is not None:
                entries.append(cur)
                cur = None
        keep = [e for e in entries if PGLOG_WORDS.search(e['text'] + ' ' +
                                                         ' '.join(e.get('more') or []))]
        out['entries'] = keep[-200:]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'PostgreSQL\'s log could not be read: %s' % str(e)[:200]
    write_here(PGLOG_FILE, json.dumps(out))


# ---- the link between the two databases, encrypted and checked (1.0.104) ----------
# The daemon makes this node's PostgreSQL a certificate from the cluster's own
# authority; this puts it in as root: the key and the certificate into the
# data folder (postgres's, 0600), the authorities into HA_CA_FILE (0644 - they
# are public, and PostgreSQL's replication workers read it), ssl on through
# ALTER SYSTEM and a reload - nothing restarts. Asked for later, the other
# node's lines in pg_hba.conf from host to hostssl. Every value is checked;
# the running server is asked over TLS whether it answers with the new
# certificate before "done" is said.
def pg_sql(port, sql, db='postgres'):
    for runner in (['runuser', '-u', 'postgres', '--'], ['sudo', '-u', 'postgres']):
        if shutil.which(runner[0]):
            got = subprocess.run(runner + ['psql', '-XAtq', '-p', str(int(port)), '-d', db,
                                           '-v', 'ON_ERROR_STOP=1', '-f', '-'],
                                 capture_output=True, text=True, timeout=60,
                                 input=sql.rstrip().rstrip(';') + ';\n')
            if got.returncode == 0:
                return got.stdout.strip()
            raise Refused('PostgreSQL said: %s' % (got.stderr or got.stdout).strip()[:300])
    raise Refused('neither runuser nor sudo is on this machine')


def pg_lit(v):
    return "'%s'" % str(v).replace("'", "''")


def pg_answers_with(port, cert_pem, ca_file):
    """The certificate this PostgreSQL shows over TLS, checked against the
    authorities - True when it is `cert_pem`."""
    import socket
    import ssl
    want = ssl.PEM_cert_to_DER_cert(cert_pem.strip() + '\n')
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.check_hostname = False          # the names are the other node's matter: verify-full
    s = socket.create_connection(('127.0.0.1', int(port)), timeout=5)
    try:
        s.sendall(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')     # SSLRequest
        if s.recv(1) != b'S':
            return False
        t = ctx.wrap_socket(s)
        try:
            return t.getpeercert(True) == want
        finally:
            t.close()
    finally:
        try:
            s.close()
        except OSError:
            pass


def pg_peer_net(text):
    import ipaddress as _ip
    a = _ip.ip_address(str(text).strip())
    return '%s/%d' % (a, 32 if a.version == 4 else 128)


def pgtls_checked(r):
    if not isinstance(r, dict):
        raise Refused('the request is not an object')
    out = {'id': str(r.get('id') or '')}
    if not re.match(r'^[0-9a-f]{8,40}\Z', out['id']):
        raise Refused('the request has no id')
    out['do'] = r.get('do')
    if out['do'] not in ('server', 'hba', 'peer', 'hba_off', 'server_off', 'ha_open'):
        raise Refused('server, hba, peer, hba_off, server_off or ha_open')
    try:
        out['port'] = int(r.get('port') or 5432)
    except (TypeError, ValueError):
        raise Refused('the port is a number')
    if not 1 <= out['port'] <= 65535:
        raise Refused('the port is 1 to 65535')
    for k in ('db', 'user'):
        if not PG_NAME_RE.match(str(r.get(k) or '')):
            raise Refused('the database and its account are plain names')
        # pg_hba's words for "every one" are not acme's
        # database or account (1.0.209): "all all" let any role in from the peer.
        if str(r[k]).lower() in PG_HBA_WORDS:
            raise Refused('%s is a word of pg_hba.conf, not acme\'s database or account' % r[k])
        # Nor the server's own (1.0.45): "host postgres postgres <peer>" opened the superuser
        # to the network.
        low = str(r[k]).lower()
        if low.startswith('pg_') or low in (('postgres', 'template0', 'template1') if k == 'db'
                                            else ('postgres', 'root', 'replication')):
            raise Refused('%s is the database server\'s own, not acme\'s' % r[k])
        out[k] = str(r[k])
    peer = str(r.get('peer') or '').strip()
    try:
        out['peer'] = str(plain(peer, 'address')) if peer else ''
    except ValueError:
        raise Refused('the other node\'s address is one plain address')
    if out['do'] == 'peer':
        try:
            out['old_peer'] = str(plain(str(r.get('old_peer') or '').strip(), 'address')) \
                if r.get('old_peer') else ''
        except ValueError:
            raise Refused('the other node\'s old address is one plain address')
        if not out['peer']:
            raise Refused('the other node\'s new address is needed')
        out['keep_old'] = bool(r.get('keep_old'))
        out['drop_old'] = bool(r.get('drop_old'))
    if out['do'] == 'ha_open':
        # The first node of a shared pair (1.0.210): the address it listens on
        # beside the ones it has, and the node being joined let in.
        if not out['peer']:
            raise Refused('the address of the node being joined is needed')
        try:
            out['listen'] = str(plain(str(r.get('listen') or '').strip(), 'address'))
        except ValueError:
            raise Refused('the address to listen on is one plain address')
    if str(r.get('ca_file') or HA_CA_FILE) != HA_CA_FILE:
        raise Refused('the authorities go into %s' % HA_CA_FILE)
    if out['do'] == 'server':
        pem = pem_set(r.get('cert'), r.get('key'))
        if not pem:
            raise Refused('the certificate and its key are missing')
        out['cert'], out['key'] = pem['cert'], pem['key']
        trust = str(r.get('trust') or '').strip()
        certs = re.findall(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----',
                           trust)
        if not certs or len(certs) > 5 or sum(len(c) for c in certs) < len(trust) - 20:
            raise Refused('the authorities are PEM certificates')
        with tempfile.TemporaryDirectory(prefix='acme-pgtls-') as t:
            cf = os.path.join(t, 'ca.pem')
            with open(cf, 'w') as f:
                f.write('\n'.join(certs) + '\n')
            sf = os.path.join(t, 'c.pem')
            with open(sf, 'w') as f:
                f.write(out['cert'])
            openssl(['verify', '-CAfile', cf, sf], 'the certificate is not from these authorities')
        out['trust'] = '\n'.join(certs) + '\n'
    return out


def pgtls_server(r):
    data = pg_path_checked(pg_sql(r['port'], 'SHOW data_directory'), folder=True)
    uid = pg_owner()
    gid = None
    try:
        import pwd
        gid = pwd.getpwnam('postgres').pw_gid
    except (KeyError, ImportError):
        pass
    # As it was, for a certificate PostgreSQL does not take (1.0.209): ssl = on
    # and the new files stayed, and its next restart could fail on them.
    was_conf = {}
    for k in ('ssl_cert_file', 'ssl_key_file', 'ssl'):
        got = pg_sql(r['port'], "SELECT setting || '|' || COALESCE(sourcefile, '') FROM "
                                "pg_settings WHERE name = %s" % pg_lit(k))
        was_conf[k] = got.split('|', 1) if '|' in got else [got, '']
    was_files = {}
    for name in ('acme-ha.key', 'acme-ha.crt'):
        try:
            was_files[name] = pg_file_read(os.path.join(data, name))     # no link (1.0.44)
        except (OSError, Refused):
            was_files[name] = None
    for name, text, mode in (('acme-ha.key', r['key'], 0o600), ('acme-ha.crt', r['cert'], 0o644)):
        path = os.path.join(data, name)
        pg_file_put(path, text, mode, uid, gid)
    os.makedirs(os.path.dirname(HA_CA_FILE), mode=0o755, exist_ok=True)
    os.chmod(os.path.dirname(HA_CA_FILE), 0o755)
    write_root(HA_CA_FILE, r['trust'], 0o644)
    if shutil.which('restorecon'):
        subprocess.run(['restorecon', '-R', os.path.dirname(HA_CA_FILE),
                        os.path.join(data, 'acme-ha.key'), os.path.join(data, 'acme-ha.crt')],
                       capture_output=True)
    pg_sql(r['port'], 'ALTER SYSTEM SET ssl_cert_file = %s' % pg_lit(os.path.join(data, 'acme-ha.crt')))
    pg_sql(r['port'], 'ALTER SYSTEM SET ssl_key_file = %s' % pg_lit(os.path.join(data, 'acme-ha.key')))
    pg_sql(r['port'], "ALTER SYSTEM SET ssl = 'on'")
    pg_sql(r['port'], 'SELECT pg_reload_conf()')
    seen = False
    for _ in range(20):
        time.sleep(0.5)
        try:
            if pg_answers_with(r['port'], r['cert'], HA_CA_FILE):
                seen = True
                break
        except Exception:                               # noqa: BLE001
            pass
    if not seen:
        try:
            for k, (setting, src) in was_conf.items():
                if src.endswith('postgresql.auto.conf'):
                    pg_sql(r['port'], 'ALTER SYSTEM SET %s = %s' % (k, pg_lit(setting)))
                else:
                    pg_sql(r['port'], 'ALTER SYSTEM RESET %s' % k)
            for name, old in was_files.items():
                path = os.path.join(data, name)
                if old is None:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                else:
                    pg_file_put(path, old, 0o600 if name.endswith('.key') else 0o644, uid, gid)
            pg_sql(r['port'], 'SELECT pg_reload_conf()')
        except Exception:                               # noqa: BLE001
            pass
        raise Refused('PostgreSQL did not take the certificate on reload - its log says why '
                      '(Settings → High availability → The errors); it is as it was')
    end = openssl(['x509', '-noout', '-enddate'], 'the certificate', r['cert'])
    import ssl as _ssl
    return {'said': 'PostgreSQL answers over TLS with its certificate from the cluster\'s '
                    'authority', 'data_dir': data,
            'cert_end': float(_ssl.cert_time_to_seconds(end.strip().split('=', 1)[-1]))}


def pgtls_hba(r):
    if not r['peer']:
        raise Refused('the other node\'s address is not known here')
    net = pg_peer_net(r['peer'])
    if net.startswith('127.') or net == '::1/128':
        return {'said': 'the other node is on this machine (%s): its line in pg_hba.conf is '
                        'this node\'s own, left as it is' % r['peer']}
    hba = pg_path_checked(pg_sql(r['port'], 'SHOW hba_file'))
    if not os.path.isfile(hba):
        raise Refused('pg_hba.conf was not found (%s)' % hba[:100])
    text = pg_file_read(hba)        # not through a link (1.0.149)
    lines, changed, have_ssl = text.split('\n'), 0, False
    for i, line in enumerate(lines):
        f = line.split()
        if len(f) >= 5 and f[1] == r['db'] and f[2] == r['user'] and f[3] == net:
            if f[0] == 'host':
                lines[i] = re.sub(r'^host(\s)', r'hostssl\1', line, count=1)
                changed += 1
            elif f[0] == 'hostssl':
                have_ssl = True
    if not changed:
        if have_ssl:
            return {'said': 'pg_hba.conf already takes the other node over TLS only'}
        raise Refused('pg_hba.conf has no line of acme\'s for %s (%s %s): it was written by '
                      'hand - change host to hostssl there yourself' % (net, r['db'], r['user']))
    st = os.lstat(hba)
    pg_file_copy(hba, hba + '.acme-before-tls')
    pg_file_put(hba, '\n'.join(lines), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    try:
        pg_sql(r['port'], 'SELECT pg_reload_conf()')
        bad = pg_sql(r['port'], 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')
        if bad not in ('', '0'):
            raise Refused('PostgreSQL does not read pg_hba.conf as written')
    except Refused:
        pg_file_copy(hba + '.acme-before-tls', hba)
        pg_sql(r['port'], 'SELECT pg_reload_conf()')
        raise
    return {'said': 'the other node (%s) is let into the database over TLS only (hostssl)'
                    % r['peer']}


def pgtls_peer(r):
    """The other node moved to another address (1.0.106): acme's line for it in
    pg_hba.conf moved with it - host or hostssl as it was - or, with none, a
    host line put in front. The file as it was is kept beside it."""
    net = pg_peer_net(r['peer'])
    old = pg_peer_net(r['old_peer']) if r.get('old_peer') else ''
    hba = pg_path_checked(pg_sql(r['port'], 'SHOW hba_file'))
    if not os.path.isfile(hba):
        raise Refused('pg_hba.conf was not found (%s)' % hba[:100])
    text = pg_file_read(hba)        # not through a link (1.0.149)
    lines, moved, there = text.split('\n'), 0, False

    def ours(f):
        return len(f) >= 5 and f[0] in ('host', 'hostssl') and f[1] == r['db'] and \
            f[2] == r['user']
    olds = bool(old) and not old.startswith('127.') and old != '::1/128'
    there = any(ours(line.split()) and line.split()[3] == net for line in lines)
    if r.get('keep_old'):
        # On trial (1.0.137): the new address let in beside the old one.
        if not there:
            for i, line in enumerate(lines):
                f = line.split()
                if olds and ours(f) and f[3] == old:
                    lines.insert(i + 1, line.replace(old, net, 1))
                    moved += 1
                    there = True
                    break
    elif there or r.get('drop_old'):
        # The new one in already (kept, or going back to one kept beside it):
        # the old line out, not made a second copy of the new.
        if olds:
            keep = [line for line in lines if not (ours(line.split()) and
                                                   line.split()[3] == old)]
            moved = len(lines) - len(keep)
            lines = keep
    else:
        for i, line in enumerate(lines):
            f = line.split()
            if olds and ours(f) and f[3] == old:
                lines[i] = line.replace(old, net, 1)
                moved += 1
                there = True
    if not there:
        lines.insert(0, 'host    %s    %s    %s    scram-sha-256' % (r['db'], r['user'], net))
        lines.insert(0, '# acme high availability: the other node (%s)' % time.strftime('%Y-%m-%d'))
    new_text = '\n'.join(lines)
    if new_text == text:
        return {'said': 'pg_hba.conf already lets %s in' % r['peer']}
    st = os.lstat(hba)
    pg_file_copy(hba, hba + '.acme-before-readdress')
    pg_file_put(hba, new_text, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    try:
        pg_sql(r['port'], 'SELECT pg_reload_conf()')
        bad = pg_sql(r['port'], 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')
        if bad not in ('', '0'):
            raise Refused('PostgreSQL does not read pg_hba.conf as written')
    except Refused:
        pg_file_copy(hba + '.acme-before-readdress', hba)
        pg_sql(r['port'], 'SELECT pg_reload_conf()')
        raise
    return {'said': 'pg_hba.conf lets the other node in from %s%s' % (
        r['peer'], (' (was %s)' % r['old_peer']) if moved else '')}


def pgtls_hba_off(r):
    """TLS switched off (1.0.107): the other node's hostssl line back to host."""
    if not r['peer']:
        return {'said': 'the other node\'s address is not known here: nothing changed'}
    net = pg_peer_net(r['peer'])
    if net.startswith('127.') or net == '::1/128':
        return {'said': 'the other node is on this machine: nothing changed'}
    hba = pg_path_checked(pg_sql(r['port'], 'SHOW hba_file'))
    if not os.path.isfile(hba):
        raise Refused('pg_hba.conf was not found (%s)' % hba[:100])
    text = pg_file_read(hba)        # not through a link (1.0.149)
    lines, changed = text.split('\n'), 0
    for i, line in enumerate(lines):
        f = line.split()
        if len(f) >= 5 and f[0] == 'hostssl' and f[1] == r['db'] and f[2] == r['user'] and \
                f[3] == net:
            lines[i] = re.sub(r'^hostssl(\s)', r'host\1', line, count=1)
            changed += 1
    if not changed:
        return {'said': 'pg_hba.conf already lets the other node in without TLS'}
    st = os.lstat(hba)
    pg_file_copy(hba, hba + '.acme-before-tls-off')
    pg_file_put(hba, '\n'.join(lines), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    pg_sql(r['port'], 'SELECT pg_reload_conf()')
    return {'said': 'the other node (%s) is let in with or without TLS again' % r['peer']}


def pgtls_server_off(r):
    """TLS switched off (1.0.107): ssl and its files as they were before acme
    (ALTER SYSTEM RESET - postgresql.conf says again), the cluster's key and
    certificate taken out of the data folder, the authority file away."""
    data = pg_sql(r['port'], 'SHOW data_directory')
    for k in ('ssl_cert_file', 'ssl_key_file', 'ssl'):
        pg_sql(r['port'], 'ALTER SYSTEM RESET %s' % k)
    pg_sql(r['port'], 'SELECT pg_reload_conf()')
    time.sleep(1)
    now = pg_sql(r['port'], 'SHOW ssl')
    gone = []
    try:
        data = pg_path_checked(data, folder=True)
    except Refused:
        data = ''
    if data:
        for name in ('acme-ha.key', 'acme-ha.crt'):
            try:
                os.unlink(os.path.join(data, name))
                gone.append(name)
            except FileNotFoundError:
                pass
    try:
        os.unlink(HA_CA_FILE)
        gone.append(HA_CA_FILE)
    except FileNotFoundError:
        pass
    return {'said': 'PostgreSQL is as it was before (ssl = %s, by postgresql.conf); taken '
                    'away: %s' % (now, ', '.join(gone) or 'nothing')}


def pg_restart_here(port):
    """This PostgreSQL started again (1.0.210) - its systemd unit, or Debian's
    pg_ctlcluster - and waited for until it answers."""
    major = int(pg_sql(port, 'SHOW server_version_num')) // 10000
    done = ''
    if not NO_SERVICES and shutil.which('systemctl'):
        for unit in ('postgresql-%d' % major, 'postgresql@%d-main' % major, 'postgresql'):
            if subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                              capture_output=True).returncode == 0:
                got = subprocess.run(['systemctl', 'restart', unit], capture_output=True,
                                     text=True, timeout=120)
                if got.returncode != 0:
                    raise Refused('systemctl restart %s: %s' % (unit, (got.stderr or '').strip()[-200:]))
                done = unit
                break
    if not done and shutil.which('pg_lsclusters'):
        for line in subprocess.run(['pg_lsclusters', '-h'], capture_output=True,
                                   text=True).stdout.splitlines():
            f = line.split()
            if len(f) >= 3 and f[2] == str(int(port)):
                got = subprocess.run(['pg_ctlcluster', f[0], f[1], 'restart'], capture_output=True,
                                     text=True, timeout=120)
                if got.returncode != 0:
                    raise Refused('pg_ctlcluster %s %s restart: %s' % (
                        f[0], f[1], (got.stderr or '').strip()[-200:]))
                done = 'cluster %s/%s' % (f[0], f[1])
                break
    if not done:
        raise Refused('PostgreSQL could not be restarted: no service of it was found - '
                      'restart it yourself')
    for _ in range(60):
        try:
            if pg_sql(port, 'SELECT 1') == '1':
                return done
        except Refused:
            pass
        time.sleep(1)
    raise Refused('PostgreSQL did not come back after its restart (%s)' % done)


def pg_hba_ha_line(r, text):
    """pg_hba.conf with a line for the node being joined in front - hostssl
    when this PostgreSQL has TLS on - or None when one is there already."""
    net = pg_peer_net(r['peer'])
    for line in text.split('\n'):
        f = line.split()
        if len(f) >= 4 and f[0] in ('host', 'hostssl') and f[1] == r['db'] and f[2] == r['user'] \
                and f[3] == net:
            return None, f[0]
    kind = 'hostssl' if pg_sql(r['port'], 'SHOW ssl') == 'on' else 'host'
    line = '%s    %s    %s    %s    scram-sha-256' % (kind, r['db'], r['user'], net)
    return ('# acme high availability: the node being joined (%s)\n%s\n%s'
            % (time.strftime('%Y-%m-%d'), line, text)), kind


def pgtls_ha_open(r):
    """PostgreSQL on the first node of a shared pair opened to the node being
    joined (1.0.210), what  acme --ha-setup --ha-shared  does as root, asked
    from the pages: it listens on this node's address too, pg_hba.conf lets
    the other node in (scram-sha-256), it is reloaded - restarted when it has
    to listen anew - and is checked to answer there."""
    import socket
    steps = []
    listen = pg_sql(r['port'], 'SHOW listen_addresses')
    words = [w.strip() for w in listen.split(',') if w.strip()]
    restart = False
    if '*' in words or '0.0.0.0' in words or r['listen'] in words or \
            ('::' in words and ':' in r['listen']):
        steps.append({'key': 'listen', 'ok': True, 'said': 'PostgreSQL listens on %s already '
                      '(listen_addresses = %s)' % (r['listen'], listen)})
    else:
        new = ','.join(words + [r['listen']])
        pg_sql(r['port'], 'ALTER SYSTEM SET listen_addresses = %s' % pg_lit(new))
        restart = True
        steps.append({'key': 'listen', 'ok': True, 'said': 'listen_addresses = %s (was %s)'
                      % (new, listen or "''")})
    hba = pg_path_checked(pg_sql(r['port'], 'SHOW hba_file'))
    if not os.path.isfile(hba):
        raise Refused('pg_hba.conf was not found (%s)' % hba[:100])
    text = pg_file_read(hba)
    new_text, kind = pg_hba_ha_line(r, text)
    if new_text is None:
        steps.append({'key': 'hba', 'ok': True, 'said': 'pg_hba.conf lets %s in already (%s)'
                      % (r['peer'], kind)})
    else:
        st = os.lstat(hba)
        pg_file_copy(hba, hba + '.acme-before-join')
        pg_file_put(hba, new_text, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        try:
            pg_sql(r['port'], 'SELECT pg_reload_conf()')
            bad = pg_sql(r['port'], 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')
            if bad not in ('', '0'):
                raise Refused('PostgreSQL does not read pg_hba.conf as written')
        except Refused:
            pg_file_copy(hba + '.acme-before-join', hba)
            pg_sql(r['port'], 'SELECT pg_reload_conf()')
            raise
        steps.append({'key': 'hba', 'ok': True, 'said': '%s: %s %s %s %s scram-sha-256' % (
            hba, kind, r['db'], r['user'], pg_peer_net(r['peer']))})
    if restart:
        how = pg_restart_here(r['port'])
        steps.append({'key': 'restart', 'ok': True, 'said': 'PostgreSQL started again to listen '
                      'on the network (%s)' % how})
    else:
        pg_sql(r['port'], 'SELECT pg_reload_conf()')
        steps.append({'key': 'restart', 'ok': True, 'said': 'PostgreSQL read its configuration '
                      'again (no restart needed)'})
    ok = False
    try:
        s = socket.create_connection((r['listen'], r['port']), timeout=4)
        s.close()
        ok = True
    except OSError as e:
        why = str(e)
    steps.append({'key': 'answers', 'ok': ok, 'said': ('PostgreSQL answers at %s:%d' % (
        r['listen'], r['port'])) if ok else ('PostgreSQL does not answer at %s:%d: %s' % (
            r['listen'], r['port'], why))})
    return {'said': '; '.join(x['said'] for x in steps), 'steps': steps}


def pgtls_part():
    d = web_fd()
    try:
        raw = read_req(PGTLS_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(PGTLS_ASK, d)
        return
    drop_ask(PGTLS_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        out['id'] = str((r or {}).get('id') or '')[:40] if isinstance(r, dict) else ''
        r = pgtls_checked(r)
        out.update({'server': pgtls_server, 'peer': pgtls_peer, 'hba': pgtls_hba,
                    'hba_off': pgtls_hba_off, 'server_off': pgtls_server_off,
                    'ha_open': pgtls_ha_open}[r['do']](r))
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(PGTLS_FILE, json.dumps(out))



# ---- a database and its account made on this machine's server (1.0.210) -------------
# Settings → The database → Move to another database → "Make the database and the
# account for me": PostgreSQL as its own postgres account (runuser), MariaDB as
# root over its socket - no administrator's password typed anywhere. Asked in
# dbmake.ask, answered in dbmake.json (without the password); as root by hand:
# acme_web.py --dbmake, the request as JSON on stdin.
DBMAKE_ASK = 'dbmake.ask'
DBMAKE_FILE = 'dbmake.json'
DBMAKE_PW_RE = re.compile(r'^[\x21-\x7e]{8,128}\Z')
DBMAKE_USERS_PG = ('postgres', 'root', 'replication')
DBMAKE_USERS_MY = ('root', 'mysql', 'mariadb.sys', 'debian-sys-maint', 'mysql.sys',
                   'mysql.session', 'mysql.infoschema')
DBMAKE_DBS_PG = ('postgres', 'template0', 'template1')
DBMAKE_DBS_MY = ('mysql', 'sys', 'information_schema', 'performance_schema')


def dbmake_checked(r):
    if not isinstance(r, dict):
        raise Refused('the request is not an object')
    eng = r.get('engine')
    if eng not in ('postgres', 'mariadb'):
        raise Refused('the engine is postgres or mariadb')
    for k in ('name', 'user'):
        if not PG_NAME_RE.match(str(r.get(k) or '')):
            raise Refused('%s is letters, digits and _ only, starting with a letter' % k)
    # Never an account or a database of the server's own (1.0.44): asked by the acme account,
    # ALTER ROLE postgres / ALTER USER root would have given it the server's administrator -
    # and through it (COPY ... TO PROGRAM) a shell as postgres.
    reserved_users = DBMAKE_USERS_PG if eng == 'postgres' else DBMAKE_USERS_MY
    reserved_dbs = DBMAKE_DBS_PG if eng == 'postgres' else DBMAKE_DBS_MY
    if str(r['user']).lower() in reserved_users or str(r['user']).lower().startswith('pg_'):
        raise Refused('%s is an account of the database server itself - not one made here'
                      % r['user'])
    if str(r['name']).lower() in reserved_dbs:
        raise Refused('%s is a database of the server itself - not one made here' % r['name'])
    pw = str(r.get('password') or '')
    if not DBMAKE_PW_RE.match(pw) or "'" in pw or '\\' in pw:
        raise Refused('the password is 8 to 128 printable characters, without \' and \\')
    try:
        port = int(r.get('port') or (5432 if eng == 'postgres' else 3306))
    except (TypeError, ValueError):
        raise Refused('the port is a number')
    if not 0 < port < 65536:
        raise Refused('the port is a number')
    return {'engine': eng, 'name': r['name'], 'user': r['user'], 'password': pw, 'port': port}


def dbmake_pg(r):
    name, user = r['name'], r['user']
    said = []
    # Not into the server's log: the statement with the password in it.
    quiet = "SET log_statement = 'none';\nSET log_min_error_statement = 'panic';\n"
    have = pg_sql(r['port'], "SELECT 1 FROM pg_roles WHERE rolname = %s" % pg_lit(user))
    verb = 'ALTER' if have == '1' else 'CREATE'
    if verb == 'ALTER' and pg_sql(r['port'], (
            "SELECT 1 FROM pg_roles WHERE rolname = %s AND (rolsuper OR rolcreaterole OR "
            "rolcreatedb OR rolreplication OR rolbypassrls)") % pg_lit(user)) == '1':
        raise Refused('the account %s is there with rights over the whole server - its password '
                      'is not changed from here; choose another name' % user)
    pg_sql(r['port'], quiet + '%s ROLE "%s" WITH LOGIN PASSWORD %s' % (verb, user, pg_lit(r['password'])))
    said.append('the account %s %s' % (user, 'was there: its password is new' if verb == 'ALTER'
                                       else 'is made'))
    if pg_sql(r['port'], "SELECT 1 FROM pg_database WHERE datname = %s" % pg_lit(name)) == '1':
        pg_sql(r['port'], 'ALTER DATABASE "%s" OWNER TO "%s"' % (name, user))
        said.append('the database %s was there: %s owns it now' % (name, user))
    else:
        try:
            pg_sql(r['port'], "CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE template0 "
                              "LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'" % (name, user))
        except Refused:
            pg_sql(r['port'], "CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE template0"
                   % (name, user))
        said.append('the database %s is made, owned by %s' % (name, user))
    pg_sql(r['port'], 'GRANT ALL ON SCHEMA public TO "%s"' % user, db=name)
    return said


def dbmake_my(r):
    name, user, pw = r['name'], r['user'], r['password']
    prog = shutil.which('mariadb') or shutil.which('mysql')
    if not prog:
        raise Refused('neither mariadb nor mysql (the client) is on this machine')
    # An account that is there with rights over the whole server: not taken over (1.0.44).
    got = subprocess.run([prog, '--protocol=socket', '-u', 'root', '--batch', '-N', '-e',
                          "SELECT COUNT(*) FROM mysql.user WHERE User = '%s' AND (Super_priv = 'Y' "
                          "OR Grant_priv = 'Y' OR Create_user_priv = 'Y' OR File_priv = 'Y' OR "
                          "Shutdown_priv = 'Y' OR Process_priv = 'Y')" % user],
                         capture_output=True, text=True, timeout=60)
    if got.returncode == 0 and got.stdout.strip() not in ('', '0'):
        raise Refused("the account '%s' is there with rights over the whole server - its "
                      "password is not changed from here; choose another name" % user)
    sql = ['SET SESSION sql_log_off = 1;',
           'CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;' % name]
    for at in ('localhost', '127.0.0.1', '::1'):
        sql += ["CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s';" % (user, at, pw),
                "ALTER USER '%s'@'%s' IDENTIFIED BY '%s';" % (user, at, pw),
                "GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';" % (name, user, at)]
    sql.append('FLUSH PRIVILEGES;')
    got = subprocess.run([prog, '--protocol=socket', '-u', 'root', '--batch'], input='\n'.join(sql) + '\n',
                         capture_output=True, text=True, timeout=60)
    if got.returncode != 0:
        raise Refused('MariaDB said: %s' % (got.stderr or got.stdout).replace(pw, '…').strip()[:300])
    return ['the database %s (utf8mb4, compared byte for byte)' % name,
            "the account '%s' on localhost, 127.0.0.1 and ::1, with every right on %s and none "
            "elsewhere" % (user, name)]


def dbmake_do(raw):
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8') if isinstance(raw, bytes) else raw)
        out['id'] = str((r or {}).get('id') or '')[:40] if isinstance(r, dict) else ''
        r = dbmake_checked(r)
        out['said'] = (dbmake_pg if r['engine'] == 'postgres' else dbmake_my)(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    return out


def dbmake_part():
    d = web_fd()
    try:
        raw = read_req(DBMAKE_ASK, 16384)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(DBMAKE_ASK, d)
        return
    drop_ask(DBMAKE_ASK, d)
    write_here(DBMAKE_FILE, json.dumps(dbmake_do(raw)))

# ---- the machine's network, its name, and switching it off (1.0.119) ----------------
# Asked in net.ask: what the network is now (read), a new one put in
# NetworkManager with the host name and /etc/hosts (apply), or a reboot or a
# power-off (power). Every value checked here again: addresses by ipaddress,
# names by NAME_RE, the connection by the list NetworkManager gives.
NET_ASK = 'net.ask'
NET_FILE = 'net.json'
NMCLI = os.environ.get('ACME_NMCLI', 'nmcli')
HOSTNAMECTL = os.environ.get('ACME_HOSTNAMECTL', 'hostnamectl')
HOSTS_FILE = os.environ.get('ACME_HOSTS_FILE', '/etc/hosts')
POWER_CMD = os.environ.get('ACME_POWER_CMD', '')        # tests: a file to write instead
# What the machine had before a change on trial (1.0.139): root's alone - the
# acme account may write /etc/acme, and what is put back from here runs as root.
NET_SNAP_DIR = os.environ.get('ACME_NET_SNAP_DIR', '/var/lib/acme-net')
NET_SNAP_FILE = 'before.json'
NET_PROFILE_DIRS = tuple(x for x in os.environ.get(
    'ACME_NM_PROFILE_DIRS', '/etc/NetworkManager/system-connections/:'
    '/etc/sysconfig/network-scripts/:/run/NetworkManager/system-connections/').split(':') if x)
NET_SYSCTL6 = os.environ.get('ACME_SYSCTL6', '/etc/sysctl.d/90-acme-ipv6.conf')


def nm_fields(con, fields):
    out = run([NMCLI, '-t', '-g', ','.join(fields), 'connection', 'show', con],
              'nmcli connection show')
    vals = out.rstrip('\n').split('\n')
    got = {}
    for k, v in zip(fields, vals + [''] * (len(fields) - len(vals))):
        got[k] = v.replace('\\:', ':').strip()
    return got


def nm_list(text):
    return [x.strip() for x in re.split(r'[,\s]+', text or '') if x.strip() and x.strip() != '--']


def net_read():
    out = {'nm': bool(shutil.which(NMCLI)), 'devices': [], 'con': '', 'dev': '', 'conf': {},
           'live': {'addrs4': [], 'addrs6': [], 'gw4': '', 'gw6': '', 'dns': []}}
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6') as f:
            out['ipv6_kernel'] = f.read().strip() == '0'
    except OSError:
        out['ipv6_kernel'] = False
    try:
        for line in run(['ip', '-o', 'addr', 'show'], 'ip addr').splitlines():
            f = line.split()
            if len(f) < 4 or f[1] == 'lo':
                continue
            try:
                ifc = ipaddress.ip_interface(f[3])
            except ValueError:
                continue
            if ifc.ip.is_loopback or ifc.ip.is_link_local:
                continue
            (out['live']['addrs4'] if ifc.version == 4 else out['live']['addrs6']).append(
                {'addr': str(ifc), 'dev': f[1].split('@')[0]})
        for fam, key in (('-4', 'gw4'), ('-6', 'gw6')):
            r = run(['ip', fam, 'route', 'show', 'default'], 'ip route', ok=(0, 1, 2))
            m = re.search(r'default via (\S+) dev (\S+)', r)
            if m:
                out['live'][key] = m.group(1)
                if key == 'gw4':
                    out['dev'] = m.group(2)
    except Refused:
        pass
    try:
        with open('/etc/resolv.conf') as f:
            out['live']['dns'] = [l.split()[1] for l in f if l.startswith('nameserver ')
                                  and len(l.split()) > 1][:6]
    except OSError:
        pass
    try:
        out['hostname'] = run([HOSTNAMECTL, '--static'], 'hostnamectl').strip() or \
            os.uname().nodename
    except (Refused, OSError):
        out['hostname'] = os.uname().nodename
    if not out['nm']:
        return out
    try:
        for line in run([NMCLI, '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device'],
                        'nmcli device').splitlines():
            f = line.replace('\\:', '\x00').split(':')
            f = [x.replace('\x00', ':') for x in f]
            if len(f) >= 4 and f[1] in ('ethernet', 'bond', 'vlan', 'bridge', 'team', 'wifi'):
                out['devices'].append({'dev': f[0], 'type': f[1], 'state': f[2], 'con': f[3]})
    except Refused as e:
        out['nm_said'] = str(e)
    dev = out['dev'] or next((d['dev'] for d in out['devices'] if d['con']), '')
    con = next((d['con'] for d in out['devices'] if d['dev'] == dev and d['con']), '')
    out['dev'], out['con'] = dev, con
    if con:
        try:
            g = nm_fields(con, ['ipv4.method', 'ipv4.addresses', 'ipv4.gateway', 'ipv4.dns',
                                'ipv4.dns-search', 'ipv6.method', 'ipv6.addresses',
                                'ipv6.gateway', 'ipv6.dns'])
            out['conf'] = {'ipv4_method': g['ipv4.method'],
                           'ipv4_addresses': nm_list(g['ipv4.addresses']),
                           'ipv4_gateway': g['ipv4.gateway'] if g['ipv4.gateway'] != '--' else '',
                           'ipv4_dns': nm_list(g['ipv4.dns']),
                           'ipv4_search': nm_list(g['ipv4.dns-search']),
                           'ipv6_method': g['ipv6.method'],
                           'ipv6_addresses': nm_list(g['ipv6.addresses']),
                           'ipv6_gateway': g['ipv6.gateway'] if g['ipv6.gateway'] != '--' else '',
                           'ipv6_dns': nm_list(g['ipv6.dns'])}
        except Refused as e:
            out['nm_said'] = str(e)
    return out


def net_checked(r):
    """An apply request, every value in its one shape."""
    out = {'con': str(r.get('con') or ''), 'reboot_in': 0}
    if not out['con'] or len(out['con']) > 120 or any(c in out['con'] for c in '\n\r\x00'):
        raise Refused('which connection?')
    v4 = r.get('ipv4') or {}
    try:
        a4 = plain(v4.get('addr'), 'interface')
    except ValueError:
        raise Refused('the IPv4 address is an address with its prefix (192.0.2.10/24)')
    if a4.version != 4 or '/' not in str(v4.get('addr')):
        raise Refused('the IPv4 address is an address with its prefix (192.0.2.10/24)')
    out['addr4'] = str(a4)
    gw = str(v4.get('gw') or '').strip()
    if gw:
        try:
            g = plain(gw, 'address')
        except ValueError:
            raise Refused('the gateway is one IPv4 address')
        if g.version != 4 or g not in a4.network:
            raise Refused('the gateway %s is not in %s' % (g, a4.network))
        out['gw4'] = str(g)
    else:
        out['gw4'] = ''
    dns = []
    for d in (v4.get('dns') or [])[:4] + ((r.get('ipv6') or {}).get('dns') or [])[:4]:
        try:
            dns.append(str(plain(d, 'address')))
        except ValueError:
            raise Refused('%r is not the address of a DNS server' % str(d)[:60])
    out['dns4'] = [d for d in dns if ':' not in d]
    out['dns6'] = [d for d in dns if ':' in d]
    search = []
    for s_ in (v4.get('search') or [])[:6]:
        if not NAME_RE.match(str(s_)):
            raise Refused('%r is not a domain' % str(s_)[:60])
        search.append(str(s_))
    out['search'] = search
    v6 = r.get('ipv6') or {}
    mode = str(v6.get('mode') or 'off')
    if mode not in ('off', 'auto', 'manual', 'keep'):
        raise Refused('IPv6 is off, auto, manual or keep')
    out['mode6'] = mode
    if mode == 'manual':
        try:
            a6 = plain(v6.get('addr'), 'interface')
        except ValueError:
            raise Refused('the IPv6 address is an address with its prefix (2001:db8::10/64)')
        if a6.version != 6 or a6.ip.is_link_local or '/' not in str(v6.get('addr')):
            raise Refused('the IPv6 address is a global one with its prefix (2001:db8::10/64)')
        out['addr6'] = str(a6)
        g6 = str(v6.get('gw') or '').strip()
        if g6:
            try:
                gg = plain(g6, 'address')
            except ValueError:
                raise Refused('the IPv6 gateway is one IPv6 address')
            if gg.version != 6:
                raise Refused('the IPv6 gateway is one IPv6 address')
            out['gw6'] = str(gg)
        else:
            out['gw6'] = ''
    host = str(r.get('hostname') or '').strip().rstrip('.').lower()
    # Going back may ask for a short name again - the one the machine had.
    if host and (not NAME_RE.match(host) or ('.' not in host and not r.get('rollback'))):
        raise Refused('the host name is the whole name: acme1.example.cz')
    if len(host) > 64:
        # what hostnamectl takes (1.0.51): longer, it refused it half way through the change
        raise Refused('a host name is 64 characters at most')
    out['hostname'] = host
    snap = str(r.get('snapshot') or '')
    out['snapshot'] = snap if re.match(r'^[0-9a-f]{8,40}\Z', snap) else ''
    olds = []
    for o in (r.get('old') or [])[:8]:
        try:
            olds.append(str(plain(o, 'address')))
        except ValueError:
            pass
    out['old'] = olds
    old_host = str(r.get('old_hostname') or '').strip().lower()
    out['old_hostname'] = old_host if NAME_RE.match(old_host or 'x') else ''
    try:
        out['reboot_in'] = max(0, min(600, int(r.get('reboot_in') or 0)))
    except (TypeError, ValueError):
        out['reboot_in'] = 0
    return out


def hosts_lines(text, n):
    """/etc/hosts with this machine's lines for its old addresses and names
    taken out and its new ones put in; localhost lines kept as they are."""
    short = n['hostname'].split('.')[0] if n['hostname'] else ''
    drop_names = set(x for x in (n['hostname'], short, n['old_hostname'],
                                 n['old_hostname'].split('.')[0]) if x)
    out = []
    for line in text.splitlines():
        f = line.split('#', 1)[0].split()
        if f and not f[0].startswith(('127.', '::1')):
            if f[0] in n['old'] or f[0] == n['addr4'].split('/')[0] or \
                    any(x.lower() in drop_names for x in f[1:]):
                continue
        out.append(line)
    if n['hostname']:
        out.append('%s %s %s    # this machine - written by acme' % (
            n['addr4'].split('/')[0], n['hostname'], short))
        if n.get('addr6'):
            out.append('%s %s %s    # this machine - written by acme' % (
                n['addr6'].split('/')[0], n['hostname'], short))
    return '\n'.join(out) + '\n'


def power_after(what, secs):
    """A reboot or a power-off a few seconds from now - after this helper
    has written its answer and the page has had it."""
    secs = max(3, int(secs or 5))
    if POWER_CMD:
        with open(POWER_CMD, 'a') as f:
            f.write('%s %d %s\n' % (what, secs, time.time()))
        return '%s in %d s (written to %s)' % (what, secs, POWER_CMD)
    if NO_SERVICES:
        return '%s in %d s (not here: tests)' % (what, secs)
    run(['systemd-run', '--on-active=%ds' % secs, '--unit',
         'acme-%s-%d' % (what, int(time.time())), '/usr/bin/systemctl', what],
        'systemd-run %s' % what)
    return '%s in %d s' % (what, secs)


def net_apply(n):
    if not shutil.which(NMCLI):
        raise Refused('NetworkManager (nmcli) is not on this machine: set the network by hand')
    cons = [l.replace('\\:', ':') for l in run([NMCLI, '-t', '-g', 'NAME', 'connection',
                                                'show'], 'nmcli connection show').splitlines()]
    if n['con'] not in cons:
        raise Refused('there is no connection %r here' % n['con'])
    said = []
    before = nm_fields(n['con'], ['ipv4.method', 'ipv4.addresses', 'ipv4.gateway', 'ipv4.dns',
                                  'ipv4.dns-search', 'ipv6.method', 'ipv6.addresses',
                                  'ipv6.gateway', 'ipv6.dns'])
    # The old addresses and name taken out of /etc/hosts only as this machine has
    # them now (1.0.209): taken as the request said, any line of it - the
    # directory's, the repository's - could be taken away.
    have = set()
    for key in ('ipv4.addresses', 'ipv6.addresses'):
        for a in nm_list(before.get(key)):
            have.add(a.split('/')[0])
    n['old'] = [o for o in n['old'] if o in have]
    try:
        host_was = run([HOSTNAMECTL, '--static'], 'hostnamectl').strip().lower()
    except Exception:                                   # noqa: BLE001
        host_was = ''
    if n['old_hostname'] and n['old_hostname'] not in (host_was, host_was.split('.')[0]):
        n['old_hostname'] = ''
    if n.get('snapshot'):
        said.append(net_snapshot(n['con'], n['snapshot']))
    args = [NMCLI, 'connection', 'modify', n['con'],
            'ipv4.method', 'manual', 'ipv4.addresses', n['addr4'],
            'ipv4.gateway', n['gw4'], 'ipv4.dns', ','.join(n['dns4']),
            'ipv4.dns-search', ','.join(n['search']), 'ipv4.ignore-auto-dns', 'yes']
    if n['mode6'] == 'off':
        args += ['ipv6.method', 'disabled', 'ipv6.addresses', '', 'ipv6.gateway', '',
                 'ipv6.dns', '']
    elif n['mode6'] == 'auto':
        args += ['ipv6.method', 'auto', 'ipv6.addresses', '', 'ipv6.gateway', '',
                 'ipv6.dns', ','.join(n['dns6'])]
    elif n['mode6'] == 'manual':
        args += ['ipv6.method', 'manual', 'ipv6.addresses', n['addr6'],
                 'ipv6.gateway', n['gw6'], 'ipv6.dns', ','.join(n['dns6'])]
    run(args, 'nmcli connection modify')
    try:
        return _net_apply_rest(n, said, before)
    except BaseException:
        # Half way (1.0.51): the new address stayed in the profile - the next reboot brought the
        # node up on it, the change marked failed. The profile as it was put back.
        back = [NMCLI, 'connection', 'modify', n['con']]
        for k in ('ipv4.method', 'ipv4.addresses', 'ipv4.gateway', 'ipv4.dns', 'ipv4.dns-search',
                  'ipv6.method', 'ipv6.addresses', 'ipv6.gateway', 'ipv6.dns'):
            if k in before:
                v = before.get(k) or ''
                back += [k, '' if v == '--' else v]
        try:
            run(back, 'nmcli connection modify (put back)')
        except Exception:                               # noqa: BLE001
            pass
        raise


def _net_apply_rest(n, said, before):
    said.append('NetworkManager: %s - %s via %s, DNS %s%s' % (
        n['con'], n['addr4'], n['gw4'] or 'no gateway', ', '.join(n['dns4']) or 'none',
        {'off': ', IPv6 off', 'auto': ', IPv6 automatic',
         'manual': ', IPv6 %s' % n.get('addr6'), 'keep': ''}[n['mode6']]))
    if n['mode6'] in ('auto', 'manual'):
        # IPv6 switched off in the kernel by an earlier hand: on again.
        f6 = NET_SYSCTL6
        write_root(f6, '%s\nnet.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.'
                   'disable_ipv6 = 0\n' % MARK, 0o644)
    if n['hostname']:
        run([HOSTNAMECTL, 'set-hostname', n['hostname']], 'hostnamectl set-hostname')
        said.append('host name: %s' % n['hostname'])
    try:
        with open(HOSTS_FILE) as f:
            had = f.read()
    except OSError:
        had = '127.0.0.1 localhost localhost.localdomain\n::1 localhost localhost.localdomain\n'
    new = hosts_lines(had, n)
    if new != had:
        try:
            write_root(HOSTS_FILE + '.acme-before', had, 0o644)
        except OSError:
            pass
        write_root(HOSTS_FILE, new, 0o644)
        said.append('%s: this machine\'s lines' % HOSTS_FILE)
    if n['reboot_in']:
        said.append(power_after('reboot', n['reboot_in']))
    return {'said': said, 'before': before}


def _read_or_none(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def nm_props(con):
    """Every ipv4.* and ipv6.* property of the connection, as nmcli shows it."""
    out = {}
    for line in run([NMCLI, '-t', '-f', 'ipv4,ipv6', 'connection', 'show', con],
                    'nmcli connection show').splitlines():
        k, sep, v = line.partition(':')
        if sep and re.match(r'^ipv[46]\.[a-z0-9-]+\Z', k):
            out[k] = v.replace('\\:', ':')
    return out


def net_snapshot(con, snap_id):
    """Everything of the machine's network a change touches, kept as it is now
    (1.0.139): the connection's profile whole - every address, route, MTU,
    DHCP or not - its ipv4/ipv6 properties, the host name, /etc/hosts and
    the IPv6 switch. Going back puts exactly this back."""
    profile_path, profile = '', None
    try:
        got = run([NMCLI, '-t', '-g', 'GENERAL.FILENAME', 'connection', 'show', con],
                  'nmcli connection show').strip()
        if got.startswith(NET_PROFILE_DIRS) and '/../' not in got:
            profile_path, profile = got, _read_or_none(got)
    except Refused:
        pass
    try:
        host = run([HOSTNAMECTL, '--static'], 'hostnamectl').strip()
    except (Refused, OSError):
        host = ''
    snap = {'id': snap_id, 'at': time.time(), 'con': con, 'profile_path': profile_path,
            'profile': profile, 'props': nm_props(con), 'hostname': host,
            'hosts': _read_or_none(HOSTS_FILE), 'sysctl6': _read_or_none(NET_SYSCTL6)}
    os.makedirs(NET_SNAP_DIR, mode=0o700, exist_ok=True)
    os.chmod(NET_SNAP_DIR, 0o700)
    write_root(os.path.join(NET_SNAP_DIR, NET_SNAP_FILE), json.dumps(snap), 0o600)
    return 'what the machine has now kept, to go back to: %s' % (
        'the whole profile of %s' % con if profile is not None
        else 'the IPv4 and IPv6 settings of %s' % con)


def net_restore(r):
    """The network as it was before the change on trial: the profile put back
    whole, the host name, /etc/hosts and the IPv6 switch - then a reboot."""
    snap_id = str(r.get('snapshot') or '')
    try:
        with open(os.path.join(NET_SNAP_DIR, NET_SNAP_FILE)) as f:
            snap = json.load(f)
    except (OSError, ValueError):
        raise Refused('nothing kept to go back to on this machine')
    if not isinstance(snap, dict) or not snap_id or snap.get('id') != snap_id:
        raise Refused('what is kept here is of another change (%s)' % str(
            (snap or {}).get('id') if isinstance(snap, dict) else '?')[:20])
    con = str(snap.get('con') or '')
    said = []
    path, profile = str(snap.get('profile_path') or ''), snap.get('profile')
    done = False
    if profile is not None and path.startswith(NET_PROFILE_DIRS) and '/../' not in path:
        st = None
        try:
            st = os.stat(path)
        except OSError:
            pass
        write_root(path, profile, stat.S_IMODE(st.st_mode) if st else 0o600)
        try:
            run([NMCLI, 'connection', 'load', path], 'nmcli connection load')
            done = True
            said.append('NetworkManager: the profile of %s put back as it was' % con)
        except Refused as e:
            said.append('the profile could not be loaded (%s) - its settings put back one by '
                        'one' % e)
    if not done:
        props = snap.get('props') or {}
        args = [NMCLI, 'connection', 'modify', con]
        for k in sorted(props):
            v = props[k]
            args += [k, '' if v in ('--', None) else v]
        try:
            run(args, 'nmcli connection modify')
            said.append('NetworkManager: every IPv4 and IPv6 setting of %s put back' % con)
        except Refused:
            keys = ('ipv4.method', 'ipv4.addresses', 'ipv4.gateway', 'ipv4.dns',
                    'ipv4.dns-search', 'ipv4.routes', 'ipv4.ignore-auto-dns', 'ipv6.method',
                    'ipv6.addresses', 'ipv6.gateway', 'ipv6.dns', 'ipv6.routes')
            args = [NMCLI, 'connection', 'modify', con]
            for k in keys:
                if k in props:
                    args += [k, '' if props[k] in ('--', None) else props[k]]
            run(args, 'nmcli connection modify')
            said.append('NetworkManager: the addresses, routes and DNS of %s put back' % con)
    host = str(snap.get('hostname') or '')
    if host and NAME_RE.match(host):
        run([HOSTNAMECTL, 'set-hostname', host], 'hostnamectl set-hostname')
        said.append('host name: %s' % host)
    if snap.get('hosts') is not None:
        write_root(HOSTS_FILE, snap['hosts'], 0o644)
        said.append('%s as it was' % HOSTS_FILE)
    if snap.get('sysctl6') is None:
        if os.path.exists(NET_SYSCTL6):
            os.unlink(NET_SYSCTL6)
    else:
        write_root(NET_SYSCTL6, snap['sysctl6'], 0o644)
    try:
        reboot_in = max(0, min(600, int(r.get('reboot_in') or 0)))
    except (TypeError, ValueError):
        reboot_in = 0
    if reboot_in:
        said.append(power_after('reboot', reboot_in))
    return {'said': said}


def net_part():
    d = web_fd()
    try:
        raw = read_req(NET_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(NET_ASK, d)
        return
    drop_ask(NET_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        what = r.get('do')
        if what == 'read':
            out['data'] = net_read()
        elif what == 'apply':
            out['data'] = net_apply(net_checked(r))
        elif what == 'restore':
            out['data'] = net_restore(r)
        elif what == 'power':
            how = r.get('how')
            if how not in ('reboot', 'poweroff'):
                raise Refused('reboot or poweroff')
            try:
                secs = int(r.get('in') or 5)
            except (TypeError, ValueError):
                secs = 5
            out['data'] = {'said': [power_after(how, secs)]}
        else:
            raise Refused('read, apply, restore or power')
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NET_FILE, json.dumps(out))


# ---- the time: chrony (1.0.120) ---------------------------------------------------
# Asked in ntp.ask: how the clock is (read), chrony's servers set (apply), a
# step to the right time now (sync). /etc/chrony.conf keeps everything of its
# own; when acme sets the servers, the file's own server/pool/makestep/allow
# lines are commented out (#acme#) and acme's block is added between marks -
# put back as they were when acme stops setting them.
NTP_ASK = 'ntp.ask'
NTP_FILE = 'ntp.json'
CHRONYC = os.environ.get('ACME_CHRONYC', 'chronyc')
TIMEDATECTL = os.environ.get('ACME_TIMEDATECTL', 'timedatectl')
# Debian and Ubuntu read /etc/chrony/chrony.conf (1.0.146): the other was
# written there and never read, and "applied" said so.
CHRONY_CONF = os.environ.get('ACME_CHRONY_CONF') or next(
    (p for p in ('/etc/chrony.conf', '/etc/chrony/chrony.conf') if os.path.isfile(p)),
    '/etc/chrony.conf')
NTP_BEGIN = '# ---- acme: the time servers, set on its pages (Settings - Time) ----'
NTP_END = '# ---- acme: end ----'
NTP_KEYS = ('server', 'pool', 'peer', 'makestep', 'allow', 'minsources', 'maxdistance', 'sourcedir')
TZ_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_+-]{0,39}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z')   # no -option (otp 1.0.234)


def ntp_read():
    out = {'chrony': bool(shutil.which(CHRONYC)), 'tracking': {}, 'sources': [], 'stats': {}}
    try:
        t = run([TIMEDATECTL, 'show'], 'timedatectl', ok=(0, 1))
        for line in t.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                if k in ('Timezone', 'NTP', 'NTPSynchronized', 'LocalRTC', 'CanNTP'):
                    out[k.lower()] = v
    except (Refused, OSError):
        pass
    out['time'] = time.time()
    if not out['chrony']:
        return out
    try:
        f = run([CHRONYC, '-c', 'tracking'], 'chronyc tracking').strip().split(',')
        if len(f) >= 14:
            out['tracking'] = {'ref_id': f[0], 'ref': f[1], 'stratum': int(f[2] or 0),
                               'ref_time': float(f[3] or 0), 'offset': float(f[4] or 0),
                               'last_offset': float(f[5] or 0), 'rms': float(f[6] or 0),
                               'freq': float(f[7] or 0), 'skew': float(f[9] or 0),
                               'root_delay': float(f[10] or 0), 'root_disp': float(f[11] or 0),
                               'interval': float(f[12] or 0), 'leap': f[13]}
    except (Refused, ValueError, OSError) as e:
        out['said'] = str(e)[:200]
    try:
        for line in run([CHRONYC, '-c', 'sources'], 'chronyc sources').splitlines():
            f = line.split(',')
            if len(f) < 10:
                continue
            try:
                out['sources'].append({'mode': f[0], 'state': f[1], 'name': f[2][:120],
                                       'stratum': int(f[3] or 0), 'poll': int(f[4] or 0),
                                       'reach': int(f[5] or 0, 8) if f[5] else 0,
                                       'last_rx': int(f[6]) if f[6].lstrip('-').isdigit() else None,
                                       'offset': float(f[7] or 0), 'measured': float(f[8] or 0),
                                       'error': float(f[9] or 0)})
            except ValueError:
                continue
    except (Refused, OSError):
        pass
    try:
        with open(CHRONY_CONF) as f:
            text = f.read()
        out['managed'] = NTP_BEGIN in text
        out['own'] = [l.strip() for l in text.splitlines()
                      if l.strip().split(' ')[0] in ('server', 'pool', 'peer')][:20]
    except OSError:
        out['managed'] = False
    return out


def ntp_checked(r):
    out = {'manage': bool(r.get('manage')), 'servers': [], 'allow': [],
           'makestep': [1.0, 3], 'minsources': 1, 'timezone': '', 'peers': []}
    for x in (r.get('servers') or [])[:12]:
        if not isinstance(x, dict):
            raise Refused('a server is an object')
        host = str(x.get('host') or '').strip().lower().rstrip('.')
        try:
            host = str(plain(host, 'address'))
        except ValueError:
            if not NAME_RE.match(host):
                raise Refused('%r is not a host name or an address' % host[:80])
        out['servers'].append({'host': host, 'pool': bool(x.get('pool')),
                               'iburst': bool(x.get('iburst', True)),
                               'prefer': bool(x.get('prefer')), 'nts': bool(x.get('nts'))})
    for p in (r.get('peers') or [])[:2]:
        try:
            out['peers'].append(str(plain(p, 'address')))
        except ValueError:
            raise Refused('%r is not the other node\'s address' % str(p)[:60])
    for a in (r.get('allow') or [])[:20]:
        try:
            out['allow'].append(str(plain(a, 'network')))
        except ValueError:
            raise Refused('%r is not a network (192.0.2.0/24)' % str(a)[:60])
    try:
        th = float((r.get('makestep') or [1.0, 3])[0])
        lim = int((r.get('makestep') or [1.0, 3])[1])
    except (TypeError, ValueError, IndexError):
        raise Refused('makestep is a threshold in seconds and a number of updates')
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise Refused('makestep: 0.001 - 3600 s, and -1 (always) to 1000 updates')
    out['makestep'] = [th, lim]
    try:
        out['minsources'] = max(1, min(10, int(r.get('minsources') or 1)))
    except (TypeError, ValueError):
        out['minsources'] = 1
    tz = str(r.get('timezone') or '').strip()
    if tz and not TZ_RE.match(tz):
        raise Refused('%r is not a time zone' % tz[:60])
    out['timezone'] = tz
    if out['manage'] and not out['servers'] and not out['peers']:
        raise Refused('at least one time server')
    return out


def ntp_conf_text(text, n):
    """chrony.conf with acme's block (or without it, put back as it was)."""
    lines = text.splitlines()
    out, inside = [], False
    for l in lines:
        if l.strip() == NTP_BEGIN:
            inside = True
            continue
        if l.strip() == NTP_END:
            inside = False
            continue
        if inside:
            continue
        if l.startswith('#acme# '):
            l = l[7:]                       # the file's own line, put back first (1.0.51: 7 -
            #                                 a space more each time it was applied)
        out.append(l)
    if not n['manage']:
        return '\n'.join(out).rstrip('\n') + '\n'
    kept = []
    for l in out:
        if (l.split() or [''])[0] in NTP_KEYS:      # a tab after the word too (1.0.51)
            kept.append('#acme# ' + l)
        else:
            kept.append(l)
    block = [NTP_BEGIN]
    for x in n['servers']:
        opts = [o for o, on in (('iburst', x['iburst']), ('prefer', x['prefer']),
                                ('nts', x['nts'])) if on]
        block.append('%s %s %s' % ('pool' if x['pool'] else 'server', x['host'], ' '.join(opts)))
    for p in n['peers']:
        # The other node of the cluster: one more source, and allowed to ask.
        block.append('server %s iburst' % p)
        block.append('allow %s' % p)
    for a in n['allow']:
        block.append('allow %s' % a)
    block.append('makestep %s %d' % (('%g' % n['makestep'][0]), n['makestep'][1]))
    if n['minsources'] > 1:
        block.append('minsources %d' % n['minsources'])
    block.append(NTP_END)
    return '\n'.join([l.rstrip() for l in kept]).rstrip('\n') + '\n\n' + '\n'.join(block) + '\n'


def ntp_apply(n):
    said = []
    if not shutil.which(CHRONYC) and not NO_SERVICES:
        if shutil.which('dnf'):
            run(['dnf', '-y', 'install', 'chrony'], 'dnf install chrony')
            said.append('chrony installed')
        else:
            raise Refused('chrony is not on this machine')
    try:
        with open(CHRONY_CONF) as f:
            had = f.read()
    except FileNotFoundError:
        had = 'driftfile /var/lib/chrony/drift\nrtcsync\nlogdir /var/log/chrony\n'
    new = ntp_conf_text(had, n)
    if new != had:
        if NTP_BEGIN not in had:
            try:
                write_root(CHRONY_CONF + '.acme-before', had, 0o644)
            except OSError:
                pass
        write_root(CHRONY_CONF, new, 0o644)
        said.append('%s: %s' % (CHRONY_CONF, ', '.join(x['host'] for x in n['servers'])
                                if n['manage'] else 'its own servers again'))
        if not NO_SERVICES and not os.environ.get('ACME_NTP_NO_SERVICE'):
            run(['systemctl', 'enable', '--now', 'chronyd'], 'systemctl enable chronyd')
            run(['systemctl', 'restart', 'chronyd'], 'systemctl restart chronyd')
            said.append('chronyd restarted')
    if n['timezone']:
        try:
            cur = run([TIMEDATECTL, 'show', '-p', 'Timezone', '--value'], 'timedatectl').strip()
        except Refused:
            cur = ''
        if cur != n['timezone']:
            run([TIMEDATECTL, 'set-timezone', n['timezone']], 'timedatectl set-timezone')
            said.append('time zone: %s' % n['timezone'])
    if not NO_SERVICES and shutil.which(TIMEDATECTL) and not os.environ.get('ACME_NTP_NO_SERVICE'):
        run([TIMEDATECTL, 'set-ntp', 'true'], 'timedatectl set-ntp', ok=(0, 1))
    return {'said': said}


def ntp_part():
    d = web_fd()
    try:
        raw = read_req(NTP_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(NTP_ASK, d)
        return
    drop_ask(NTP_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        what = r.get('do')
        if what == 'read':
            out['data'] = ntp_read()
            if r.get('zones'):
                try:
                    out['data']['zones'] = run([TIMEDATECTL, 'list-timezones'],
                                               'timedatectl').split()[:700]
                except Refused:
                    pass
        elif what == 'apply':
            out['data'] = ntp_apply(ntp_checked(r))
        elif what == 'sync':
            said = run([CHRONYC, 'makestep'], 'chronyc makestep').strip()
            run([CHRONYC, 'burst', '4/4'], 'chronyc burst', ok=(0, 1))
            out['data'] = {'said': [said or 'stepped']}
        else:
            raise Refused('read, apply or sync')
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NTP_FILE, json.dumps(out))


def status_read():
    """What this helper wrote last. It lies in the folder the acme account
    owns, so nothing of it is trusted (1.0.57): what is used again - the
    peer, its family, the interface, the DH choices - is checked again."""
    try:
        got = json.loads(read_req('status.json').decode('utf-8'))
    except (OSError, ValueError, Refused):
        return {}
    if not isinstance(got, dict):
        return {}
    a = got.get('applied') if isinstance(got.get('applied'), dict) else {}
    keep = {}
    try:
        if a.get('peer'):
            keep['peer'] = str(plain(a['peer'], 'address'))
            keep['family'] = 6 if ':' in keep['peer'] else 4
        if a.get('iface') and IFACE_RE.match(str(a['iface'])):
            keep['iface'] = str(a['iface'])
    except ValueError:
        keep = {}
    got['applied'] = keep
    dh = got.get('dh') if isinstance(got.get('dh'), dict) else {}
    got['dh'] = {k: v for k, v in dh.items() if k in ('node', 'vip') and v in DH_CHOICES}
    return got


# ---- the acme console when root signs in (1.0.141) ---------------------------------
# Asked in console.ask from the pages (Settings - About): on or off, written to
# /etc/acme-console-login as `acme --console-at-login` writes it.
CONSOLE_ASK = 'console.ask'
CONSOLE_FILE = 'console.json'
CONSOLE_FLAG = os.environ.get('ACME_CONSOLE_FLAG', '/etc/acme-console-login')


USER_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z')


def console_flag_read():
    """(root on, the normal users it opens for: '*', a list, or []) - from the file itself, never
    through a link. The second line (1.0.240): 'users: *' or 'users: alice bob'."""
    try:
        fd = os.open(CONSOLE_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False, []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False, []
        text = os.read(fd, 8192).decode('utf-8', 'replace')
    finally:
        os.close(fd)
    lines = text.split('\n')
    users = []
    for ln in lines[1:]:
        if ln.startswith('users:'):
            words = ln[6:].split()
            users = '*' if words == ['*'] else [w for w in words if USER_NAME_RE.match(w)][:200]
    return lines[0].strip() == 'on', users


def console_users_checked(users):
    if users is None or users == '*':
        return users
    if not isinstance(users, list) or len(users) > 200:
        raise Refused('the users: "*" or a list of names, 200 at most')
    out = []
    for u in users:
        if not isinstance(u, str) or not USER_NAME_RE.match(u) or u == 'root':
            raise Refused('%r is not the name of a normal user' % str(u)[:40])
        if u not in out:
            out.append(u)
    return out


def console_flag_set(on, users=None):
    """Written beside it and put in its place: a link or a pipe found there is
    replaced, never followed. `users` None: as they were (1.0.240)."""
    if users is None:
        users = console_flag_read()[1]
    text = ('on\n' if on else 'off\n')
    if users:
        text += 'users: %s\n' % ('*' if users == '*' else ' '.join(users))
    tmp = '%s.%d.tmp' % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, CONSOLE_FLAG)


def console_part():
    d = web_fd()
    try:
        raw = read_req(CONSOLE_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(CONSOLE_ASK, d)
        return
    drop_ask(CONSOLE_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        if r.get('do') != 'set' or not isinstance(r.get('on'), bool):
            raise Refused('set, on or off')
        console_flag_set(r['on'], console_users_checked(r.get('users')))
        on, users = console_flag_read()
        out['data'] = {'on': on, 'users': users}
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(CONSOLE_FILE, json.dumps(out))


# ---- the SSH keys root signs in with (1.0.158) ---------------------------------------
SSHKEYS_ASK = 'sshkeys.ask'
SSHKEYS_FILE = 'sshkeys.json'
ROOT_AUTH = os.environ.get('ACME_ROOT_AUTHKEYS', '/root/.ssh/authorized_keys')
KEY_TYPES = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
             'ssh-rsa', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com')
KEY_LINE_RE = re.compile(r'^(?P<type>[a-z0-9@.-]+) (?P<blob>[A-Za-z0-9+/]{40,16000}={0,3})'
                         r'(?: (?P<comment>[^\x00-\x1f\x7f]{0,200}))?\Z')


def key_facts(line):
    """(bits, SHA256:..., type) of one public key line, read by ssh-keygen."""
    got = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], input=line + '\n',
                         capture_output=True, text=True, timeout=20)
    m = re.match(r'^(\d+) (SHA256:[A-Za-z0-9+/=]+) .*\((\w+)\)\s*$', got.stdout.strip())
    if got.returncode != 0 or not m:
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def auth_lines():
    """The lines of root's authorized_keys - none where it is not there. Never
    through a link."""
    try:
        fd = os.open(ROOT_AUTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise Refused('%s cannot be read: %s' % (ROOT_AUTH, e))
    with os.fdopen(fd, 'r', encoding='utf-8', errors='replace') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused('%s is not a plain file' % ROOT_AUTH)
        return f.read(1 << 20).split('\n')


AUTH_KEYS_MOST = 300     # lines looked at by ssh-keygen (1.0.44): a user's own file is theirs


def auth_keys(lines):
    out = []
    for i, ln in enumerate(lines):
        t = ln.strip()
        if not t or t.startswith('#'):
            continue
        # A file of 50 000 lines made root run ssh-keygen 50 000 times, each other ask waiting.
        facts = key_facts(t) if len(out) < AUTH_KEYS_MOST and len(t) <= 16500 else None
        m = KEY_LINE_RE.match(t)
        out.append({'line': i, 'fp': facts[1] if facts else '', 'bits': facts[0] if facts else 0,
                    'type': facts[2] if facts else '?',
                    'comment': (m.group('comment') or '') if m else '',
                    'options': not bool(m), 'readable': bool(facts),
                    # The line itself, for the page's export: public halves only.
                    'text': t[:16500]})
    return out


def auth_write(lines):
    """root's authorized_keys written whole: its folder made 0700 if it is not
    there, refused if it is a link; a new file of root's, 0600, renamed in."""
    folder = os.path.dirname(ROOT_AUTH)
    try:
        st = os.lstat(folder)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise Refused('%s is not a plain folder' % folder)
    except FileNotFoundError:
        os.makedirs(folder, mode=0o700)
    try:
        if stat.S_ISLNK(os.lstat(ROOT_AUTH).st_mode):
            raise Refused('%s is a link - put the file itself there' % ROOT_AUTH)
    except FileNotFoundError:
        pass
    text = '\n'.join(lines).rstrip('\n') + '\n'
    fd, tmp = tempfile.mkstemp(prefix='.authorized_keys.', dir=folder)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'w') as f:
            fd = None
            f.write(text)
        os.replace(tmp, ROOT_AUTH)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which('restorecon') and not NO_SERVICES:
        subprocess.run(['restorecon', '-R', folder], capture_output=True)


def sshd_says():
    """What sshd makes of root and of keys: a key is no use where it does not
    let root in with one."""
    if not shutil.which('sshd'):
        return {'there': False}
    got = subprocess.run(['sshd', '-T'], capture_output=True, text=True, timeout=20)
    said = {}
    for ln in got.stdout.splitlines():
        k, _, v = ln.partition(' ')
        if k in ('permitrootlogin', 'pubkeyauthentication', 'passwordauthentication', 'port'):
            said[k] = v.strip()
    return {'there': True, 'permit_root': said.get('permitrootlogin', ''),
            'pubkey': said.get('pubkeyauthentication', ''),
            'password': said.get('passwordauthentication', ''), 'port': said.get('port', '')}


# ---- the SSH keys of the normal users (1.0.240) -----------------------------------------
# Every user of the machine who may sign in - UID_MIN..UID_MAX of /etc/login.defs, a shell
# that is not nologin or false - and their ~/.ssh/authorized_keys, read and written by a child
# that is that user (its own UID, groups and GID): a link or anything else they put in their own
# home can only ever touch what is theirs already.
LOGIN_DEFS = os.environ.get('ACME_LOGIN_DEFS', '/etc/login.defs')
NO_SHELLS = ('nologin', 'false', 'sync', 'shutdown', 'halt')


def uid_range():
    lo, hi = 1000, 60000
    try:
        with open(LOGIN_DEFS, encoding='utf-8', errors='replace') as f:
            for ln in f:
                w = ln.split()
                if len(w) >= 2 and w[0] in ('UID_MIN', 'UID_MAX') and w[1].isdigit():
                    if w[0] == 'UID_MIN':
                        lo = int(w[1])
                    else:
                        hi = int(w[1])
    except OSError:
        pass
    return lo, hi


def normal_users():
    """[{name, uid, home, shell}] of the users who may sign in here, by name - 500 at most."""
    import pwd
    lo, hi = uid_range()
    out = []
    for p in pwd.getpwall():
        if not lo <= p.pw_uid <= hi or p.pw_uid == 65534 or not USER_NAME_RE.match(p.pw_name):
            continue
        if not p.pw_shell or os.path.basename(p.pw_shell) in NO_SHELLS:
            continue
        if not p.pw_dir.startswith('/') or p.pw_dir == '/':
            continue
        out.append({'name': p.pw_name, 'uid': p.pw_uid, 'home': p.pw_dir, 'shell': p.pw_shell})
    out.sort(key=lambda x: x['name'])
    return out[:500]


def ssh_user(name):
    """The pwd entry of a normal user of normal_users() - refused for anybody else."""
    import pwd
    name = str(name or '')
    if not USER_NAME_RE.match(name) or not any(u['name'] == name for u in normal_users()):
        raise Refused('%s is not a user who may sign in on this machine' % name[:40])
    return pwd.getpwnam(name)


def as_user(pw, fn):
    """fn() run by a child that is the user - its answer (JSON) back through a pipe."""
    rd, wr = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            os.close(rd)
            os.setgroups(os.getgrouplist(pw.pw_name, pw.pw_gid))
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            if os.getuid() != pw.pw_uid or os.geteuid() != pw.pw_uid:
                raise OSError('could not become %s' % pw.pw_name)
            os.umask(0o077)
            try:
                got = {'ok': True, 'data': fn()}
            except Refused as e:
                got = {'ok': False, 'said': str(e)}
            except OSError as e:
                got = {'ok': False, 'said': '%s: %s' % (e.filename or pw.pw_name, e.strerror or e)}
            data = json.dumps(got).encode()[:4 << 20]
            while data:
                data = data[os.write(wr, data):]
        except BaseException as e:                      # noqa: BLE001
            try:
                os.write(wr, json.dumps({'ok': False, 'said': str(e)[:300]}).encode())
            except BaseException:                       # noqa: BLE001
                pass
            code = 1
        finally:
            os._exit(code)
    os.close(wr)
    chunks = []
    with os.fdopen(rd, 'rb') as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            chunks.append(b)
    os.waitpid(pid, 0)
    try:
        got = json.loads(b''.join(chunks).decode('utf-8', 'replace') or '{}')
    except ValueError:
        got = {}
    if not got.get('ok'):
        raise Refused(got.get('said') or 'it went wrong as %s' % pw.pw_name)
    return got.get('data')


def user_auth_paths(pw):
    return os.path.join(pw.pw_dir, '.ssh'), os.path.join(pw.pw_dir, '.ssh', 'authorized_keys')


def user_auth_read(pw):
    folder, path = user_auth_paths(pw)

    def go():
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return ''
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise Refused('%s is a link - put the file itself there' % path)
            raise
        with os.fdopen(fd, 'r', encoding='utf-8', errors='replace') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Refused('%s is not a plain file' % path)
            return f.read(1 << 20)
    return (as_user(pw, go) or '').split('\n')


def user_auth_write(pw, lines):
    """~/.ssh/authorized_keys of the user, written by the user: ~/.ssh made 0700 when it is not
    there, refused when it or the file is a link; a new file, 0600, renamed in."""
    folder, path = user_auth_paths(pw)
    text = '\n'.join(lines).rstrip('\n') + '\n'

    def go():
        hs = os.lstat(pw.pw_dir)
        if stat.S_ISLNK(hs.st_mode) or not stat.S_ISDIR(hs.st_mode) or hs.st_uid != pw.pw_uid:
            raise Refused('%s is not a home folder of %s\'s own' % (pw.pw_dir, pw.pw_name))
        try:
            st = os.lstat(folder)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise Refused('%s is not a plain folder' % folder)
        except FileNotFoundError:
            os.mkdir(folder, 0o700)
        try:
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise Refused('%s is a link - put the file itself there' % path)
        except FileNotFoundError:
            pass
        fd, tmp = tempfile.mkstemp(prefix='.authorized_keys.', dir=folder)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as f:
                fd = None
                f.write(text)
            os.replace(tmp, path)
        except BaseException:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    as_user(pw, go)
    # The folder and the file by themselves, never -R (1.0.45): the user could put a link in
    # place of ~/.ssh between the write and this, and root relabelled whatever it led to.
    # restorecon takes a link as the link itself.
    if shutil.which('restorecon') and not NO_SERVICES:
        subprocess.run(['restorecon', '--', folder, path], capture_output=True)


def key_line_checked(line):
    m = KEY_LINE_RE.match(line)
    if not m or m.group('type') not in KEY_TYPES:
        raise Refused('that is not one public key line (ssh-ed25519 AAAA... comment) - '
                      'options before the key are not taken here')
    facts = key_facts(line)
    if not facts:
        raise Refused('ssh-keygen does not read that key')
    bits, fp, kind = facts
    if kind == 'RSA' and bits < 3072:
        raise Refused('an RSA key of %d bits is too weak: 3072 at least, or ed25519' % bits)
    if kind == 'DSA':
        raise Refused('DSA keys are not taken')
    return fp


def sshkeys_user_do(r, name):
    """The same as for root, for a normal user - no "last key" guard: a user's password stays."""
    pw = ssh_user(name)
    do = r.get('do')
    lines = user_auth_read(pw)
    if do == 'add':
        line = str(r.get('line') or '').strip()
        fp = key_line_checked(line)
        if not any(k['fp'] == fp for k in auth_keys(lines)):
            user_auth_write(pw, [ln for ln in lines if ln.strip()] + [line])
    elif do == 'drop':
        fp = str(r.get('fp') or '')
        hit = [k for k in auth_keys(lines) if k['fp'] and k['fp'] == fp]
        if not hit:
            raise Refused('no key %s is there' % fp)
        gone = {k['line'] for k in hit}
        user_auth_write(pw, [ln for i, ln in enumerate(lines) if i not in gone])
    elif do != 'list':
        raise Refused('list, add or drop')
    lines = user_auth_read(pw)
    return {'user': name, 'keys': [dict((k, v) for k, v in x.items() if k != 'line')
                                   for x in auth_keys(lines)],
            'file': user_auth_paths(pw)[1], 'users': normal_users(), 'sshd': sshd_says()}


def sshkeys_do(r):
    user = str(r.get('user') or 'root')
    if user != 'root':
        return sshkeys_user_do(r, user)
    do = r.get('do')
    lines = auth_lines()
    if do == 'add':
        line = str(r.get('line') or '').strip()
        m = KEY_LINE_RE.match(line)
        if not m or m.group('type') not in KEY_TYPES:
            raise Refused('that is not one public key line (ssh-ed25519 AAAA... comment) - '
                          'options before the key are not taken here')
        facts = key_facts(line)
        if not facts:
            raise Refused('ssh-keygen does not read that key')
        bits, fp, kind = facts
        if kind == 'RSA' and bits < 3072:
            raise Refused('an RSA key of %d bits is too weak: 3072 at least, or ed25519' % bits)
        if kind == 'DSA':
            raise Refused('DSA keys are not taken')
        # There already is no fault: a key of root's the app was handed, or
        # one put on again (1.0.159).
        if not any(k['fp'] == fp for k in auth_keys(lines)):
            lines = [ln for ln in lines if ln.strip()] + [line]
            auth_write(lines)
    elif do == 'drop':
        fp = str(r.get('fp') or '')
        keys = auth_keys(lines)
        hit = [k for k in keys if k['fp'] and k['fp'] == fp]
        if not hit:
            raise Refused('no key %s is there' % fp)
        if len(keys) == len(hit) and not r.get('last_ok'):
            raise Refused('that is the last key root signs in with here - said again to take it '
                          'away anyway')
        gone = {k['line'] for k in hit}
        auth_write([ln for i, ln in enumerate(lines) if i not in gone])
    elif do != 'list':
        raise Refused('list, add or drop')
    lines = auth_lines()
    return {'keys': [dict((k, v) for k, v in x.items() if k != 'line') for x in auth_keys(lines)],
            'file': ROOT_AUTH, 'sshd': sshd_says(), 'user': 'root',
            # Who else may sign in here (1.0.240): their keys on the pages too.
            'users': normal_users()}


def sshkeys_part():
    d = web_fd()
    try:
        raw = read_req(SSHKEYS_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(SSHKEYS_ASK, d)
        return
    drop_ask(SSHKEYS_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = sshkeys_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(SSHKEYS_FILE, json.dumps(out))


# ---- the local users of the machine (1.0.243) ----------------------------------------
# Made and looked after from Settings -> Local users, on every node of a cluster or on one:
# only the users of the range login.defs gives normal users (UID_MIN..UID_MAX) - never root,
# never an account of the system or of a service. root is read, never changed. A password
# comes as a hash only (made on the node it was typed on), handed to chpasswd -e on its
# standard input - never on a command line. Each change done is said back with the list.
USERS_ASK, USERS_FILE = 'users.ask', 'users.json'
SHADOW = os.environ.get('ACME_SHADOW', '/etc/shadow')
SHELLS_FILE = os.environ.get('ACME_SHELLS', '/etc/shells')
PW_HASH_RE = re.compile(r'^\$(?:6|5|y|gy|2b|2y)\$[./A-Za-z0-9$=]{16,300}\Z')
GECOS_RE = re.compile(r'^[^:\n\x00-\x1f\x7f]{0,120}\Z')
KEEP_NAMES = ('root', 'acme', 'acme-web', 'postgres', 'mysql', 'nginx', 'apache', 'nobody',
              'keepalived', 'chrony', 'sshd', 'polkitd', 'dbus', 'systemd-network', 'tss')


def lu_run(argv, data=None):
    """A tool of shadow-utils, its error said back - never with a secret among the words."""
    got = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=120)
    if got.returncode != 0:
        msg = ((got.stderr or got.stdout or '').strip().splitlines() or ['exit %d' % got.returncode])[-1]
        raise Refused('%s: %s' % (os.path.basename(argv[0]), msg[:300]))
    return got.stdout


def lu_admin_group():
    """The group whose members may become root with sudo: wheel (RHEL) or sudo (Debian)."""
    import grp
    for g in ('wheel', 'sudo'):
        try:
            grp.getgrnam(g)
            return g
        except KeyError:
            continue
    return ''


def lu_shells():
    out = []
    try:
        with open(SHELLS_FILE, encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith('/') and not ln.startswith('#') and ' ' not in ln and ln not in out and \
                        os.path.basename(ln) not in NO_SHELLS:
                    out.append(ln)
    except OSError:
        pass
    if not out and os.path.exists('/bin/bash'):
        out.append('/bin/bash')
    nl = '/usr/sbin/nologin' if os.path.exists('/usr/sbin/nologin') else '/sbin/nologin'
    return out[:20] + [nl]


def lu_shadow():
    """{name: (hash field, last change in days, max days, expire day)} - read as root."""
    out = {}
    try:
        with open(SHADOW, encoding='utf-8', errors='replace') as f:
            for ln in f:
                p = ln.rstrip('\n').split(':')
                if len(p) >= 8:
                    # (hash, last change, max days, expire day, min days, warn days)
                    out[p[0]] = (p[1], p[2], p[4], p[7], p[3], p[5])
    except OSError:
        pass
    return out


def lu_one(p, sh, admin, today):
    import grp
    h, last, mx, exp, mn, warn = (tuple(sh.get(p.pw_name, ())) + ('',) * 6)[:6]
    groups = sorted({g.gr_name for g in grp.getgrall() if p.pw_name in g.gr_mem} |
                    ({grp.getgrgid(p.pw_gid).gr_name} if _gid_ok(p.pw_gid) else set()))
    plain = h.lstrip('!')
    # Locked: a password put out of use (! before a real hash) or the account expired - a user
    # with no password at all ('!' or '!!' alone) is not, a key lets them in.
    locked = (h.startswith('!') and plain.startswith('$')) or (exp.isdigit() and int(exp) <= today)
    return {'name': p.pw_name, 'uid': p.pw_uid, 'gecos': p.pw_gecos.split(',')[0][:120],
            'home': p.pw_dir, 'shell': p.pw_shell,
            'login': bool(p.pw_shell) and os.path.basename(p.pw_shell) not in NO_SHELLS,
            'groups': groups[:40], 'sudo': bool(admin) and admin in groups,
            'password': bool(plain) and plain not in ('*', '!', 'x') and plain.startswith('$'),
            'locked': bool(locked), 'must_change': last == '0',
            'changed': int(last) if last.isdigit() and last != '0' else None,
            'expires': int(exp) if exp.isdigit() else None,
            'max_days': int(mx) if mx.isdigit() and int(mx) < 99999 else None,
            # A user's own password aging (1.0.43, as otp 1.0.245): the day it runs out too.
            'min_days': int(mn) if mn.isdigit() else None,
            'warn_days': int(warn) if warn.isdigit() else None,
            'pw_ends': (int(last) + int(mx)) if (last.isdigit() and last != '0' and mx.isdigit()
                                                 and int(mx) < 99999) else None,
            'home_there': os.path.isdir(p.pw_dir)}


def _gid_ok(gid):
    import grp
    try:
        grp.getgrgid(gid)
        return True
    except KeyError:
        return False


def lu_list():
    import pwd
    lo, hi = uid_range()
    sh, admin, today = lu_shadow(), lu_admin_group(), int(time.time() // 86400)
    users, used = [], []
    for p in pwd.getpwall():
        if lo <= p.pw_uid <= hi:
            used.append(p.pw_uid)
        if p.pw_name == 'root' or (lo <= p.pw_uid <= hi and p.pw_uid != 65534 and
                                   USER_NAME_RE.match(p.pw_name) and p.pw_name not in KEEP_NAMES):
            u = lu_one(p, sh, admin, today)
            u['root'] = p.pw_name == 'root'
            users.append(u)
    users.sort(key=lambda u: (not u['root'], u['name']))
    return {'users': users[:500], 'uid_min': lo, 'uid_max': hi, 'used': sorted(set(used))[:5000],
            'names': sorted(p.pw_name for p in pwd.getpwall())[:5000],
            'admin_group': admin, 'shells': lu_shells(), 'today': today,
            # The password policy as in effect here, read from the files (1.0.43, as otp 1.0.245).
            'policy': pwp_read()}


def lu_target(name):
    """The pwd entry of a user this may change - refused for root, the system and services."""
    import pwd
    name = str(name or '')
    if not USER_NAME_RE.match(name) or name in KEEP_NAMES:
        raise Refused('%s is not a local user this may change' % name[:40])
    try:
        p = pwd.getpwnam(name)
    except KeyError:
        return None
    lo, hi = uid_range()
    if not lo <= p.pw_uid <= hi or p.pw_uid == 65534:
        raise Refused('%s is an account of the system (UID %d) - not changed here' % (name, p.pw_uid))
    return p


def lu_hash_checked(h):
    h = str(h or '')
    if not PW_HASH_RE.match(h):
        raise Refused('the password does not come as a hash this takes')
    return h


# ---- the password policy of the local users (1.0.43, as otp 1.0.245) -------------------------
# Settings -> Local users -> Password policy: one policy for the cluster, put in by each node's
# root helper into the system's own files - so that it holds however a password is changed
# (passwd, a password run out at sign-in, the pages): pam_pwquality's drop-in, pam_pwhistory's
# and pam_faillock's files (acme's lines between marks), login.defs' aging (the values before
# kept to be put back), and with authselect the features that put the modules in PAM. Not
# managed (the default): nothing is written, and what was written is taken out again.
SEC_DIR = os.environ.get('ACME_SECURITY_DIR', '/etc/security')
PAM_DIR = os.environ.get('ACME_PAM_DIR', '/etc/pam.d')
AUTHSELECT = os.environ.get('ACME_AUTHSELECT', shutil.which('authselect') or '')
PWQ_DROPIN = 'pwquality.conf.d/50-acme.conf'
PWQ_LEGACY = 'pwquality.conf.d/90-acme.conf'         # acme 1.0.42's own, taken out
PWP_MARK_A = '# ---- acme: Settings -> Local users -> Password policy (from here) ----\n'
PWP_MARK_B = '# ---- acme: (to here) ----\n'
PWP_WAS = '# acme-was: '
# Root's own (1.0.44): in /var/lib/acme, the acme account's, a list written there by it made root
# take out any authselect feature (without-nullok, with-pamaccess...). Only the two features the
# policy ever switches on are taken from it, too.
PWP_ORIG = os.environ.get('ACME_PWP_ORIG') or os.path.join(NET_SNAP_DIR, 'pwpolicy-orig.json')
PWP_FEATURES = ('with-pwhistory', 'with-faillock')
PWQ_KEYS = ('minlen', 'minclass', 'maxrepeat', 'dictcheck', 'usercheck', 'enforce_for_root',
            'difok', 'retry', 'dcredit', 'ucredit', 'lcredit', 'ocredit', 'maxclassrepeat')
PWQ_DEFAULT = {'minlen': 8, 'minclass': 0, 'maxrepeat': 0, 'dictcheck': 1, 'usercheck': 1,
               'enforce_for_root': 0, 'difok': 1, 'retry': 1}
DEFS_KEYS = ('PASS_MAX_DAYS', 'PASS_MIN_DAYS', 'PASS_WARN_AGE')


def pwp_conf_read(path, flags=('enforce_for_root', 'even_deny_root')):
    """key = value lines (and lone flags) of a pam module's file, comments left out."""
    out = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.split('#', 1)[0].strip()
                if not ln:
                    continue
                if '=' in ln:
                    k, v = [x.strip() for x in ln.split('=', 1)]
                    out[k] = v
                elif ln in flags:
                    out[ln] = '1'
    except OSError:
        pass
    return out


def pwp_int(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def pwp_pam():
    """Which of pwquality, pwhistory and faillock the PAM stack of the system uses."""
    files = ['system-auth', 'password-auth', 'common-password', 'common-auth', 'common-account']
    text = ''
    for f in files:
        try:
            with open(os.path.join(PAM_DIR, f), encoding='utf-8', errors='replace') as fh:
                text += fh.read() + '\n'
        except OSError:
            continue
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith('#')]

    def has(m):
        return any(m in ln for ln in lines)
    return {'pwquality': has('pam_pwquality'), 'pwhistory': has('pam_pwhistory'),
            'faillock': has('pam_faillock'), 'read': bool(text.strip())}


def pwp_authselect():
    """{profile, features} of authselect, or None where it does not manage PAM."""
    if not AUTHSELECT or not os.path.exists(AUTHSELECT):
        return None
    got = subprocess.run([AUTHSELECT, 'current', '--raw'], capture_output=True, text=True, timeout=30)
    if got.returncode != 0 or not got.stdout.strip():
        return None
    words = got.stdout.split()
    return {'profile': words[0], 'features': words[1:]}


def pwp_read():
    """The policy as in effect on this node, read from its files."""
    pwq = dict(PWQ_DEFAULT)
    raw = pwp_conf_read(os.path.join(SEC_DIR, 'pwquality.conf'))
    d = os.path.join(SEC_DIR, 'pwquality.conf.d')
    try:
        for name in sorted(os.listdir(d)):
            if name.endswith('.conf'):
                raw.update(pwp_conf_read(os.path.join(d, name)))
    except OSError:
        pass
    for k in PWQ_KEYS:
        if k in raw:
            pwq[k] = pwp_int(raw[k], raw[k])
    hist = pwp_conf_read(os.path.join(SEC_DIR, 'pwhistory.conf'))
    fl = pwp_conf_read(os.path.join(SEC_DIR, 'faillock.conf'), flags=('even_deny_root', 'silent', 'audit'))
    defs = {}
    try:
        with open(LOGIN_DEFS, encoding='utf-8', errors='replace') as f:
            for ln in f:
                w = ln.split()
                if len(w) >= 2 and w[0] in DEFS_KEYS:
                    defs[w[0]] = pwp_int(w[1], w[1])
    except OSError:
        pass
    pam = pwp_pam()
    return {'pwquality': pwq, 'remember': pwp_int(hist.get('remember'), 10 if pam['pwhistory'] else 0),
            'faillock': {'deny': pwp_int(fl.get('deny'), 3), 'unlock_time': pwp_int(fl.get('unlock_time'), 600),
                         'fail_interval': pwp_int(fl.get('fail_interval'), 900)},
            'aging': {'max_days': defs.get('PASS_MAX_DAYS', 99999), 'min_days': defs.get('PASS_MIN_DAYS', 0),
                      'warn_days': defs.get('PASS_WARN_AGE', 7)},
            'pam': pam, 'authselect': pwp_authselect(),
            'managed': os.path.exists(os.path.join(SEC_DIR, PWQ_DROPIN)),
            'pwscore': bool(shutil.which('pwscore'))}


def pwp_block_put(path, lines):
    """acme's lines between the marks in a file of the system: put in, replaced, or (None) taken
    out; the rest of the file as it is. A file that is not there is made only to put lines in."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise Refused('%s is not a plain file - not written' % path)
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        mode = stat.S_IMODE(st.st_mode)
    except FileNotFoundError:
        if lines is None:
            return
        text, mode = '', 0o644
    a, b = text.find(PWP_MARK_A), text.find(PWP_MARK_B)
    if lines is None and not (a >= 0 and b > a):
        return                          # none of acme's there: the file left as it is
    was = text
    if a >= 0 and b > a:
        text = text[:a] + text[b + len(PWP_MARK_B):]
    if lines is not None:
        if text and not text.endswith('\n'):
            text += '\n'
        text += PWP_MARK_A + ''.join('%s\n' % ln for ln in lines) + PWP_MARK_B
    if text != was:
        write_root(path, text, mode)


def pwp_defs_put(values):
    """login.defs' aging lines set (values) or put back as they were (None). The lines as they
    were are kept in login.defs itself, commented between acme's marks - so that whatever node
    or copy of the state puts it back, it is what the machine had."""
    st = os.lstat(LOGIN_DEFS)
    if not stat.S_ISREG(st.st_mode):
        raise Refused('%s is not a plain file - not written' % LOGIN_DEFS)
    with open(LOGIN_DEFS, encoding='utf-8', errors='replace') as f:
        text = f.read()
    before = text
    a, b = text.find(PWP_MARK_A), text.find(PWP_MARK_B)
    was = {}
    if a >= 0 and b > a:
        for ln in text[a + len(PWP_MARK_A):b].split('\n'):
            if ln.startswith(PWP_WAS):
                k, _, line = ln[len(PWP_WAS):].partition(' ')
                if k in DEFS_KEYS:
                    was[k] = line                   # '' - there was no such line
        text = text[:a] + text[b + len(PWP_MARK_B):]
    lines = text.split('\n')
    if values is not None and not was:
        for k in DEFS_KEYS:
            was[k] = next((ln for ln in lines if ln.split()[:1] == [k]), '')
    out, seen = [], set()
    for ln in lines:
        w = ln.split()
        if w and w[0] in DEFS_KEYS:
            if values is not None:
                if w[0] not in seen:
                    out.append('%s\t%s' % (w[0], values[w[0]]))
                seen.add(w[0])
                continue
            if w[0] in was:
                if w[0] not in seen and was[w[0]]:
                    out.append(was[w[0]])
                seen.add(w[0])
                continue
        out.append(ln)
    if values is not None:
        for k in DEFS_KEYS:
            if k not in seen:
                out.append('%s\t%s' % (k, values[k]))
        text = '\n'.join(out)
        if not text.endswith('\n'):
            text += '\n'
        text += PWP_MARK_A + ''.join('%s%s %s\n' % (PWP_WAS, k, was.get(k, '')) for k in DEFS_KEYS) \
            + PWP_MARK_B
    else:
        for k in DEFS_KEYS:
            if k in was and was[k] and k not in seen:
                out.append(was[k])
        text = '\n'.join(out)
    if text != before:
        write_root(LOGIN_DEFS, text, stat.S_IMODE(st.st_mode))


PWP_ORIG_OLD = os.path.join(STATE_DIR, 'pwpolicy-orig.json')    # 1.0.43's place


def pwp_orig_read():
    got = _pwp_orig_at(PWP_ORIG)
    if got or os.environ.get('ACME_PWP_ORIG'):
        return got
    # Where 1.0.43 kept it (1.0.44): taken over once - root's file only, as written then - or
    # the features it switched on were no longer known as acme's, and stayed on for good.
    old = _pwp_orig_at(PWP_ORIG_OLD)
    if old:
        try:
            pwp_orig_write(old)
            os.unlink(PWP_ORIG_OLD)
        except OSError:
            pass
    return old


def _pwp_orig_at(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        st = os.fstat(fd)
        with os.fdopen(fd) as f:
            if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
                return {}
            got = json.load(f)
        if not isinstance(got, dict):
            return {}
        got['features'] = [x for x in (got.get('features') or []) if x in PWP_FEATURES]
        return got
    except (OSError, ValueError):
        return {}


def pwp_orig_write(orig):
    if orig:
        os.makedirs(os.path.dirname(PWP_ORIG), mode=0o700, exist_ok=True)
        write_root(PWP_ORIG, json.dumps(orig), 0o600)
    else:
        try:
            os.unlink(PWP_ORIG)
        except OSError:
            pass


def pwp_checked(c):
    """The policy as asked, every value in its range - refused otherwise."""
    if not isinstance(c, dict):
        raise Refused('the policy is not an object')

    def num(k, lo, hi, default):
        v = c.get(k, default)
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise Refused('%s is a number' % k)
        if not lo <= v <= hi:
            raise Refused('%s is %d to %d' % (k, lo, hi))
        return v
    return {'managed': bool(c.get('managed')),
            'minlen': num('minlen', 6, 128, 12), 'minclass': num('minclass', 0, 4, 3),
            'maxrepeat': num('maxrepeat', 0, 20, 3), 'dictcheck': 1 if c.get('dictcheck', 1) else 0,
            'usercheck': 1 if c.get('usercheck', 1) else 0, 'difok': num('difok', 0, 20, 5),
            'remember': num('remember', 0, 50, 5),
            'max_days': num('max_days', 0, 99999, 99999), 'min_days': num('min_days', 0, 365, 0),
            'warn_days': num('warn_days', 0, 365, 7),
            'deny': num('deny', 0, 100, 0), 'unlock_time': num('unlock_time', 0, 86400, 900),
            'fail_interval': num('fail_interval', 60, 86400, 900),
            'existing': bool(c.get('existing'))}


def pwp_apply(c, spare=None):
    """Put the policy in (managed) or take acme's out again (not managed)."""
    import pwd
    c = pwp_checked(c)
    said = []
    orig = pwp_orig_read()
    sel = pwp_authselect()
    added = list(orig.get('features') or [])
    dropin = os.path.join(SEC_DIR, PWQ_DROPIN)
    # acme 1.0.42's own file of pwquality: taken out, whatever is asked now.
    legacy = os.path.join(SEC_DIR, PWQ_LEGACY)
    if os.path.lexists(legacy):
        os.unlink(legacy)
        said.append('pwquality: acme 1.0.42\'s file taken out')
    if not c['managed']:
        try:
            os.unlink(dropin)
            said.append('pwquality: acme\'s drop-in taken out')
        except FileNotFoundError:
            pass
        for f in ('pwhistory.conf', 'faillock.conf'):
            pwp_block_put(os.path.join(SEC_DIR, f), None)
        try:
            with open(LOGIN_DEFS, encoding='utf-8', errors='replace') as fh:
                marked = PWP_MARK_A in fh.read()
        except OSError:
            marked = False
        if marked:
            pwp_defs_put(None)
            said.append('login.defs: the aging as it was')
        if sel:
            for feat in added:
                if feat in sel['features']:
                    lu_run([AUTHSELECT, 'disable-feature', feat])
                    said.append('authselect: %s taken out again' % feat)
        orig.pop('features', None)
        pwp_orig_write(orig)
        return said or ['nothing of acme\'s was there']
    if os.path.islink(dropin) or (os.path.lexists(dropin) and not os.path.isfile(dropin)):
        raise Refused('%s is not a plain file - not written' % dropin)
    os.makedirs(os.path.dirname(dropin), exist_ok=True)
    text = ('# written by acme - Settings -> Local users -> Password policy\n'
            'minlen = %(minlen)d\nminclass = %(minclass)d\nmaxrepeat = %(maxrepeat)d\n'
            'dictcheck = %(dictcheck)d\nusercheck = %(usercheck)d\ndifok = %(difok)d\n'
            'retry = 3\n' % c)
    try:
        with open(dropin, encoding='utf-8') as fh:
            same = fh.read() == text
    except OSError:
        same = False
    if not same:
        write_root(dropin, text, 0o644)
    said.append('pwquality: at least %d characters, %d kinds' % (c['minlen'], c['minclass']))
    pwp_block_put(os.path.join(SEC_DIR, 'pwhistory.conf'),
                  ['remember = %d' % c['remember']] if c['remember'] else None)
    pwp_block_put(os.path.join(SEC_DIR, 'faillock.conf'),
                  ['deny = %d' % c['deny'], 'unlock_time = %d' % c['unlock_time'],
                   'fail_interval = %d' % c['fail_interval']] if c['deny'] else None)
    pwp_defs_put({'PASS_MAX_DAYS': c['max_days'], 'PASS_MIN_DAYS': c['min_days'],
                  'PASS_WARN_AGE': c['warn_days']})
    said.append('login.defs: a password good for %s days' % (c['max_days'] if c['max_days'] < 99999 else 'all'))
    if sel:
        want = (['with-pwhistory'] if c['remember'] else []) + (['with-faillock'] if c['deny'] else [])
        # Written down whatever happens (1.0.44): a second feature that failed left the first one
        # switched on and never known as acme's - never taken out again.
        try:
            for feat in want:
                if feat not in sel['features']:
                    lu_run([AUTHSELECT, 'enable-feature', feat])
                    added.append(feat)
                    said.append('authselect: %s put in' % feat)
            for feat in [f for f in added if f not in want]:
                lu_run([AUTHSELECT, 'disable-feature', feat])
                added = [f for f in added if f != feat]
                said.append('authselect: %s taken out again' % feat)
        finally:
            orig['features'] = [f for f in added if f in PWP_FEATURES]
            pwp_orig_write(orig)
    if c['existing']:
        lo, hi = uid_range()
        n = skipped = coded = 0
        sh = lu_shadow()
        sudo = {u['name']: bool(u.get('sudo')) for u in lu_list()['users']}
        for p in pwd.getpwall():
            if lo <= p.pw_uid <= hi and p.pw_uid != 65534 and p.pw_name not in KEEP_NAMES and \
                    USER_NAME_RE.match(p.pw_name):
                if not sh.get(p.pw_name, ('',))[0].lstrip('!').startswith('$'):
                    skipped += 1        # no password: a key only - never asked for a new one
                    continue
                if lu_coded(p.pw_name, spare, sudo.get(p.pw_name)):
                    coded += 1          # a code over SSH, no sudo: the password need not be known
                    continue
                lu_run(['chage', '-M', str(c['max_days']), '-m', str(c['min_days']),
                        '-W', str(c['warn_days']), p.pw_name])
                n += 1
        said.append('the aging put on %d user(s) of this node too%s%s' % (
            n, ' (%d with no password - a key only - left without)' % skipped if skipped else '',
            ' (%d asked a code by SSH, without sudo - left without)' % coded if coded else ''))
    return said


def lu_coded(name, spare, sudo):
    """Left out of the policy's aging (1.0.44, as acme 1.0.42 had it): a user SSH asks a code of
    who may not use sudo. sshd's account step asks for a password that ran out even after the
    code - one they may never have been told; one with sudo knows it (sudo asks for it)."""
    if sudo or not isinstance(spare, dict):
        return False
    return bool(spare.get('all')) or name in {str(n) for n in (spare.get('names') or [])[:500]}


def lu_aging_put(name, a):
    """A user's own aging (chage -M -m -W), every value in its range."""
    if not isinstance(a, dict):
        raise Refused('the aging is not an object')
    try:
        mx, mn, warn = int(a.get('max_days')), int(a.get('min_days')), int(a.get('warn_days'))
    except (TypeError, ValueError):
        raise Refused('the days of the aging are whole numbers')
    if not (0 <= mx <= 99999 and 0 <= mn <= 365 and 0 <= warn <= 365):
        raise Refused('the days of the aging are out of range')
    lu_run(['chage', '-M', str(mx), '-m', str(mn), '-W', str(warn), name])


LU_EXPIRY = os.path.join(NET_SNAP_DIR, 'users-expiry.json')


def lu_expiry_keep(name, day):
    """The day an account ended before it was locked: kept (day), or taken back (None)."""
    try:
        fd = os.open(LU_EXPIRY, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            kept = json.load(f) if os.fstat(f.fileno()).st_uid == 0 else {}
    except (OSError, ValueError):
        kept = {}
    if not isinstance(kept, dict):
        kept = {}
    if day is None:
        if name not in kept:
            return None
        was = kept.pop(name, None)
    else:
        kept[name] = str(day)
        was = None
    try:
        os.makedirs(NET_SNAP_DIR, mode=0o700, exist_ok=True)
        write_root(LU_EXPIRY, json.dumps(kept), 0o600)
    except OSError:
        pass
    return was


def lu_do(r):
    do = str(r.get('do') or 'list')
    name = str(r.get('name') or '')
    said = ''
    if do == 'list':
        return dict(lu_list(), said='')
    if do == 'policy':
        said = '; '.join(pwp_apply(r.get('conf'), r.get('spare')))
        return dict(lu_list(), said=said)
    p = lu_target(name)
    if r.get('hash') or do == 'password':
        lu_hash_checked(r.get('hash'))          # before anything is done
    if do == 'add':
        lo, hi = uid_range()
        uid = r.get('uid')
        gecos = str(r.get('gecos') or '')
        shell = str(r.get('shell') or '/bin/bash')
        if not GECOS_RE.match(gecos):
            raise Refused('the full name has letters that cannot be in it (a colon, a line break)')
        if shell not in lu_shells():
            raise Refused('%s is not a shell of /etc/shells here' % shell[:60])
        if p is not None:
            # There already (both nodes of the sandbox are one machine, or asked again): the
            # same UID is no fault; another is said.
            if uid not in (None, '') and int(uid) != p.pw_uid:
                raise Refused('%s is here already, with UID %d (not %s)' % (name, p.pw_uid, uid))
            said = '%s was here already' % name
        else:
            argv = ['useradd', '-m', '-s', shell, '-c', gecos, '-U']
            if uid not in (None, ''):
                uid = int(uid)
                if not lo <= uid <= hi:
                    raise Refused('UID %d is not one of a normal user here (%d to %d)' % (uid, lo, hi))
                import pwd
                try:
                    other = pwd.getpwuid(uid).pw_name
                except KeyError:
                    other = ''
                if other:
                    raise Refused('UID %d is %s\'s here' % (uid, other))
                argv += ['-u', str(uid)]
            lu_run(argv + ['--', name])
            said = '%s made' % name
        import pwd
        p = pwd.getpwnam(name)
        if r.get('sudo') is not None:
            lu_sudo(name, bool(r['sudo']))
        if r.get('hash'):
            lu_run(['chpasswd', '-e'], '%s:%s\n' % (name, lu_hash_checked(r['hash'])))
            if r.get('policy_aging') and not lu_coded(name, r.get('spare'), bool(r.get('sudo'))):
                lu_aging_put(name, r['policy_aging'])
            elif r.get('policy_aging'):
                lu_run(['chage', '-M', '-1', '-I', '-1', name])
        elif said.endswith(' made'):
            # No password (a key only): no aging - sshd's account step would ask a key's user
            # for a new password they have no old one to give for (as otp 1.0.246).
            lu_run(['chage', '-M', '-1', '-I', '-1', name])
        if r.get('must_change'):
            lu_run(['chage', '-d', '0', name])
        return dict(lu_list(), said=said)
    if p is None:
        if do == 'drop':
            return dict(lu_list(), said='%s was not here' % name)
        raise Refused('there is no user %s here' % name)
    if do == 'password':
        lu_run(['chpasswd', '-e'], '%s:%s\n' % (name, lu_hash_checked(r.get('hash'))))
        lu_run(['chage', '-d', '0' if r.get('must_change') else str(int(time.time() // 86400)), name])
        if r.get('policy_aging'):
            # Given a password: the policy's aging, as a user with one has it - unless SSH asks
            # them a code and they may not use sudo (1.0.44): they need not know that password.
            u = next((x for x in lu_list()['users'] if x['name'] == name), {})
            if not lu_coded(name, r.get('spare'), bool(u.get('sudo'))):
                lu_aging_put(name, r['policy_aging'])
        said = 'the password of %s set' % name
    elif do == 'aging':
        lu_aging_put(name, r.get('aging'))
        said = 'the password aging of %s set' % name
    elif do == 'lock':
        # The password and the account: no key lets in either (sshd asks PAM if it has expired).
        entry = lu_shadow().get(name, ('', '', '', ''))
        sh = entry[0]
        if sh and not sh.startswith('!'):
            lu_run(['usermod', '-L', name])
        # The day the account ends, as it was, kept to be put back by unlock (1.0.44): it set
        # "never" there, and an account made to end on a day did not end any more.
        if entry[3] and entry[3] != '0':
            lu_expiry_keep(name, entry[3])
        lu_run(['chage', '-E', '0', name])
        said = '%s locked' % name
    elif do == 'unlock':
        sh = lu_shadow().get(name, ('',))[0]
        if sh.startswith('!') and len(sh) > 2:
            lu_run(['usermod', '-U', name])
        was = lu_expiry_keep(name, None)
        # The day kept only while it is still ahead: an account that had ended before the lock
        # stayed shut after Unlock.
        ahead = bool(was and was.isdigit() and int(was) > int(time.time() // 86400))
        lu_run(['chage', '-E', was if ahead else '-1', name])
        said = '%s unlocked' % name
    elif do == 'sudo':
        lu_sudo(name, bool(r.get('on')))
        said = '%s %s' % (name, 'may use sudo' if r.get('on') else 'no longer uses sudo')
    elif do == 'set':
        argv = ['usermod']
        if 'gecos' in r:
            g = str(r.get('gecos') or '')
            if not GECOS_RE.match(g):
                raise Refused('the full name has letters that cannot be in it (a colon, a line break)')
            argv += ['-c', g]
        if 'shell' in r:
            s = str(r.get('shell') or '')
            if s not in lu_shells():
                raise Refused('%s is not a shell of /etc/shells here' % s[:60])
            argv += ['-s', s]
        if len(argv) > 1:
            lu_run(argv + ['--', name])
        said = '%s changed' % name
    elif do == 'drop':
        busy = subprocess.run(['pgrep', '-u', str(p.pw_uid)], capture_output=True, text=True)
        if busy.stdout.strip() and not r.get('force'):
            raise Refused('%s is signed in or runs something here - sign them out first' % name)
        lu_run(['userdel'] + (['-r'] if r.get('home') else []) + ['--', name])
        said = '%s taken away%s' % (name, ' with the home folder' if r.get('home') else '')
    else:
        raise Refused('list, add, password, aging, lock, unlock, sudo, set or drop')
    return dict(lu_list(), said=said)


def lu_sudo(name, on):
    g = lu_admin_group()
    if not g:
        raise Refused('this machine has no wheel or sudo group')
    import grp
    member = name in grp.getgrnam(g).gr_mem
    if on and not member:
        lu_run(['gpasswd', '-a', name, g])
    elif not on and member:
        lu_run(['gpasswd', '-d', name, g])


def users_part():
    d = web_fd()
    try:
        raw = read_req(USERS_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(USERS_ASK, d)
        return
    drop_ask(USERS_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = lu_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(USERS_FILE, json.dumps(out))

# ---- the SSH server and the notices at sign-in (1.0.163) --------------------------------
# acme's own drop-in, read before every other (00-acme.conf: the first value
# sshd reads of a setting is the one it keeps), checked by sshd -t before it
# is put in, and on trial: a timer of systemd's own puts the one before back
# unless Keep it comes in time - also with the daemon down, also with the
# web away. The notices: before signing in over SSH (Banner), at the console
# (/etc/issue.d or /etc/issue) and after signing in (/etc/motd.d or /etc/motd).
SSHD_ASK, SSHD_FILE = 'sshd.ask', 'sshd.json'
SSH_DIR = os.environ.get('ACME_SSH_DIR', '/etc/ssh')
ETC_DIR = os.environ.get('ACME_ETC', '/etc')
SSHD_BIN = shutil.which('sshd') or '/usr/sbin/sshd'
SSHD_DROPIN = 'sshd_config.d/00-acme.conf'
SSHD_STATE = os.path.join(SSH_DIR, '.acme-sshd-trial.json')
SSHD_PERMIT = ('yes', 'prohibit-password', 'no')
NOTICE_MARK = '# written by acme - Settings -> SSH server and notices\n'


def sshd_conf_path():
    return os.path.join(SSH_DIR, 'sshd_config')


def sshd_reads_dropins():
    """Whether sshd_config takes sshd_config.d (OpenSSH 8.2 on; RHEL 8's 8.0 does not)."""
    try:
        with open(sshd_conf_path()) as f:
            text = f.read()
    except OSError:
        return False
    return bool(re.search(r'(?im)^\s*Include\s+\S*sshd_config\.d/\*\.conf', text))


def sshd_values():
    if not os.path.exists(SSHD_BIN):
        return {}
    got = subprocess.run([SSHD_BIN, '-T', '-f', sshd_conf_path(), '-C',
                          'user=root,host=localhost,addr=127.0.0.1'],
                         capture_output=True, text=True, timeout=20)
    said = {}
    for ln in got.stdout.splitlines():
        k, _, v = ln.partition(' ')
        if k in ('port', 'permitrootlogin', 'passwordauthentication', 'pubkeyauthentication',
                 'allowusers', 'banner', 'kbdinteractiveauthentication', 'maxauthtries'):
            said[k] = v.strip() if k not in said else said[k] + ' ' + v.strip()
    return said


def _read_or(path, most=65536):
    # A plain file only (1.0.205): a FIFO put there held the helper - and every
    # request behind it - for good.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        with os.fdopen(fd, 'rb') as f:
            return f.read(most).decode('utf-8', 'replace')
    except OSError:
        return None


def _put_file(path, text, mode=0o644):
    """Written whole, beside and renamed in; never through a link."""
    folder = os.path.dirname(path)
    if os.path.islink(path) or os.path.islink(folder):
        raise Refused('%s is a link - put the file itself there' % path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.acme-')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            # On the file itself, not by its name (1.0.205): /etc/acme is the acme
            # group's to write in, and a link put in place of the temporary file
            # had root change the mode of whatever it pointed at.
            f.flush()
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which('restorecon'):
        subprocess.run(['restorecon', path], capture_output=True)


def _drop(path):
    try:
        if not os.path.islink(path):
            os.unlink(path)
    except FileNotFoundError:
        pass


def notice_paths():
    """Where the console's and the after-sign-in notices go here: a file of
    acme's own in issue.d / motd.d where agetty and pam_motd read those, else
    the one file (kept as it was beside it, put back when switched off)."""
    issue_d = os.path.join(ETC_DIR, 'issue.d')
    motd_d = os.path.join(ETC_DIR, 'motd.d')
    return {'issue': os.path.join(issue_d, 'acme.issue') if os.path.isdir(issue_d)
            else os.path.join(ETC_DIR, 'issue'),
            'motd': os.path.join(motd_d, 'acme') if os.path.isdir(motd_d)
            else os.path.join(ETC_DIR, 'motd'),
            'banner': os.path.join(SSH_DIR, 'acme-banner')}


def notice_set(where, text):
    """The notice put in at `where` (issue, motd), or taken out (text None)."""
    path = notice_paths()[where]
    whole = os.path.basename(path) in ('issue', 'motd')
    keep = path + '.acme-before'
    if text is None:
        if whole:
            had = _read_or(keep)
            cur = _read_or(path) or ''
            if had is not None and cur.startswith(NOTICE_MARK.strip()):
                _put_file(path, had)
            _drop(keep)
        else:
            _drop(path)
        return
    if whole and _read_or(keep) is None:
        cur = _read_or(path)
        if cur is not None and not cur.startswith(NOTICE_MARK.strip()):
            _put_file(keep, cur)
    body = text.rstrip() + '\n'
    if where == 'issue':
        body = body.replace('\\', '\\\\') + '\n'       # agetty reads \ escapes
    _put_file(path, (NOTICE_MARK if whole else '') + body)


def root_keys_count():
    try:
        return len([k for k in auth_keys(auth_lines()) if k.get('readable')])
    except Exception:                                   # noqa: BLE001
        return 0


def sshd_checked(c):
    """What the page asked for, made whole - checked here again."""
    if not isinstance(c, dict):
        raise Refused('the request is not an object')
    out = {'manage': bool(c.get('manage'))}
    permit = str(c.get('permit_root') or 'prohibit-password')
    if permit not in SSHD_PERMIT:
        raise Refused('root signs in with: yes, prohibit-password or no')
    out['permit_root'] = permit
    out['password'] = bool(c.get('password'))
    try:
        port = int(c.get('port') or 22)
    except (TypeError, ValueError):
        raise Refused('the port is a number')
    if not 1 <= port <= 65535:
        raise Refused('the port is 1 to 65535')
    # Not a port another service of this machine listens on (otp 1.0.234): sshd could not bind it
    # and stopped - and under SELinux the port was labelled for ssh, away from its own service.
    taken = {80: 'the web server', 443: 'the web server', 5432: 'PostgreSQL', 3306: 'MariaDB',
             25: 'mail', 53: 'DNS', 123: 'the time', 161: 'SNMP', 162: 'SNMP', 514: 'syslog',
             6514: 'syslog', 9861: 'acme\'s API', 112: 'keepalived'}
    if port in taken:
        raise Refused('port %d is %s\'s - choose another for SSH' % (port, taken[port]))
    out['port'] = port
    raw = c.get('allow_users') or ''
    # A list from the daemon (1.0.164: read as the text "['root']" before).
    users = [str(u) for u in raw if u] if isinstance(raw, list) else \
        [u for u in re.split(r'[\s,]+', str(raw)) if u]
    for u in users:
        if not re.match(r'^[A-Za-z0-9._@*?-]{1,64}\Z', u):
            raise Refused('%r is not a user name' % u)
    out['allow_users'] = users[:50]
    try:
        out['tries'] = max(1, min(10, int(c.get('tries') or 4)))
    except (TypeError, ValueError):
        out['tries'] = 4
    text = str(c.get('notice') or '').replace('\r\n', '\n')
    if len(text) > 4000:
        raise Refused('the notice is 4000 characters at most')
    if re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text):
        raise Refused('no control characters in the notice')
    out['notice'] = text
    for k in ('notice_ssh', 'notice_console', 'notice_motd'):
        out[k] = bool(c.get(k)) and bool(text.strip())
    out['radius'] = bool(c.get('radius')) and out['manage']
    raw = c.get('radius_users') or []
    ru = [str(u) for u in raw if u] if isinstance(raw, list) else \
        [u for u in re.split(r'[\s,]+', str(raw)) if u]
    for u in ru:
        if not re.match(r'^[A-Za-z0-9._@-]{1,64}\Z', u):
            raise Refused('%r is not a user name' % u)
    out['radius_users'] = ru[:100]
    out['radius_root'] = bool(c.get('radius_root'))
    out['radius_fallback'] = bool(c.get('radius_fallback')) and out['password']
    # A key and then the code (1.0.183): AuthenticationMethods for those asked.
    out['radius_with_key'] = bool(c.get('radius_with_key')) and out['radius']
    out['radius_hide'] = bool(c.get('radius_hide')) and out['radius']
    return out


# ---- SSH with a code from acme (1.0.178) ------------------------------------------------
# pam_radius in sshd's PAM: a block of acme's own at the top of the auth lines
# of /etc/pam.d/sshd, asking this node's RADIUS on 127.0.0.1 with the secret in
# /etc/acme/pam_radius.conf (0600). Root is left out unless asked; a key goes
# past PAM as always. With passwords off, nobody gets in by a password through
# PAM either. Put back with the rest when a change on trial is not kept.
PAM_BEGIN = '# acme: SSH with a code from acme (RADIUS) - Settings -> SSH server (begin)'
PAM_END = '# acme: SSH with a code from acme (RADIUS) (end)'
PAM_MOD_DIRS = ('/usr/lib64/security', '/lib64/security', '/usr/lib/x86_64-linux-gnu/security',
                '/lib/x86_64-linux-gnu/security', '/usr/lib/aarch64-linux-gnu/security',
                '/usr/lib/security', '/lib/security')


def pam_sshd_path():
    return os.path.join(ETC_DIR, 'pam.d', 'sshd')


def pam_radius_conf_path():
    # In a folder only root writes (1.0.44): in /etc/acme - the acme account's - it could put its
    # own file (another server, another secret) or a FIFO that hangs every sign-in in its place.
    return os.path.join(ETC_DIR, 'security', 'acme-pam_radius.conf')


def pam_radius_conf_legacy():
    return os.path.join(ETC_DIR, 'acme', 'pam_radius.conf')


def pam_radius_module():
    for d in PAM_MOD_DIRS:
        if os.path.exists(os.path.join(d, 'pam_radius_auth.so')):
            return os.path.join(d, 'pam_radius_auth.so')
    return ''


def pam_radius_install():
    """The module put in where it is missing - EPEL's pam_radius, Debian's
    libpam-radius-auth."""
    if pam_radius_module() or os.environ.get('ACME_NO_PKG'):
        return pam_radius_module()
    for cmd in (['dnf', '-y', 'install', 'pam_radius'],
                ['apt-get', '-y', 'install', 'libpam-radius-auth']):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            break
    if not pam_radius_module():
        raise Refused('pam_radius is not on this machine and could not be put in - on '
                      'AlmaLinux/RHEL: dnf install epel-release && dnf install pam_radius')
    return pam_radius_module()


def pam_without_ours(text):
    return re.sub(r'(?ms)^' + re.escape(PAM_BEGIN) + r'\n.*?^' + re.escape(PAM_END) + r'\n?', '',
                  text)


def pam_block(c):
    lines = [PAM_BEGIN]
    if c['radius_users']:
        lines.append('auth [success=1 default=ignore] pam_succeed_if.so quiet user notin %s'
                     % ':'.join(c['radius_users']))
    elif not c['radius_root']:
        lines.append('auth [success=1 default=ignore] pam_succeed_if.so quiet user = root')
    # skip_passwd (1.0.188): no "Password:" first - acme's gate asks for the code
    # itself (the app's, or one it mails or texts), in the one prompt it shows.
    lines.append('auth [success=done new_authtok_reqd=done ignore=ignore default=die] '
                 'pam_radius_auth.so conf=%s skip_passwd prompt_attribute%s' % (pam_radius_conf_path(),
                                                               ' localifdown' if c['radius_fallback'] else ''))
    if c['radius_fallback'] and sshd_root_code_key_only(c):
        # acme not answering (1.0.191): root, made to reach PAM for its code, gets
        # no system password - it signs in with a key only, as set.
        lines.append('auth [success=ignore default=die] pam_succeed_if.so quiet user != root')
    if not c['password']:
        # Passwords off: nobody left out of the code gets in by a password here.
        lines.append('auth requisite pam_deny.so')
    lines.append(PAM_END)
    return '\n'.join(lines) + '\n'


def pam_selinux_radius():
    """SELinux keeps sshd from asking RADIUS until authlogin_radius is on."""
    if os.environ.get('ACME_NO_PKG') or not shutil.which('getsebool') or not shutil.which('getenforce'):
        return
    if subprocess.run(['getenforce'], capture_output=True, text=True).stdout.strip() == 'Disabled':
        return
    got = subprocess.run(['getsebool', 'authlogin_radius'], capture_output=True, text=True)
    if got.returncode or got.stdout.strip().endswith('on'):
        return
    got = subprocess.run(['setsebool', '-P', 'authlogin_radius', 'on'], capture_output=True, text=True,
                         timeout=300)
    if got.returncode:
        raise Refused('SELinux: setsebool -P authlogin_radius on: %s'
                      % (got.stderr or got.stdout).strip()[-200:])


def pam_radius_conf_write(secret, port):
    if not re.match(r'^[\x21-\x7e]{8,128}\Z', str(secret or '')):
        raise Refused('the secret of acme\'s gate for SSH is missing')
    # Only acme's own gate (316): 127.0.0.1 and a port of 18129-18199, nothing else.
    try:
        port = int(port or 18129)
    except (TypeError, ValueError):
        raise Refused('the port of acme\'s gate for SSH is not a number')
    if not 18129 <= port <= 18199:
        raise Refused('the port of acme\'s gate for SSH is one of 18129-18199, not %d' % port)
    os.makedirs(os.path.dirname(pam_radius_conf_path()), mode=0o755, exist_ok=True)
    _put_file(pam_radius_conf_path(), '# acme - Settings -> SSH server; the secret of acme\'s gate '
              'for SSH on 127.0.0.1\n'
              # The source as a fourth field (1.0.178): pam_radius 2.0.1 with
              # three closed this file twice and took sshd's process down.
              '127.0.0.1:%d %s 30 127.0.0.1\n' % (int(port or 18129), secret), 0o600)


def pam_radius_conf_fp():
    """What the daemon compares with its own: a hash of the port and the
    secret pam_radius has, never the secret."""
    for line in (_read_or(pam_radius_conf_path()) or '').split('\n'):
        m = re.match(r'^127\.0\.0\.1:(\d+)\s+(\S+)', line)
        if m:
            return hashlib.sha256(('%d %s' % (int(m.group(1)), m.group(2))).encode()).hexdigest()[:12]
    return ''


def pam_skip_passwd(text):
    """Our block's pam_radius line with skip_passwd (1.0.188) and prompt_attribute
    (1.0.191: the code hidden as typed, where set), the rest as it is."""
    def one(m):
        block = m.group(0)
        for opt in ('skip_passwd', 'prompt_attribute'):
            block = re.sub(r'(?m)^(auth\b.*pam_radius_auth\.so conf=\S+)(?!.*\b%s\b)(.*)$' % opt,
                           r'\1 %s\2' % opt, block)
        return block
    return re.sub(r'(?ms)^' + re.escape(PAM_BEGIN) + r'\n.*?^' + re.escape(PAM_END) + r'$', one, text)


def pam_set(c, secret, port):
    """Our block in (or out of) sshd's PAM; the secret's file with it."""
    path = pam_sshd_path()
    text = _read_or(path)
    if text is None:
        if not c.get('radius'):
            return ''
        raise Refused('%s is not there - sshd does not use PAM here' % path)
    clean = pam_without_ours(text)
    if not c.get('radius'):
        if clean != text:
            _put_file(path, clean, 0o644)
        _drop(pam_radius_conf_path())
        _drop(pam_radius_conf_legacy())
        return 'SSH without a code from acme' if clean != text else ''
    pam_radius_install()
    pam_selinux_radius()
    pam_radius_conf_write(secret, port)
    lines = clean.split('\n')
    at = next((i for i, l in enumerate(lines)
               if re.match(r'^\s*(auth\b|@include\s+common-auth|-?auth\b)', l)), None)
    if at is None:
        raise Refused('%s has no auth lines - put the block in by hand' % path)
    lines[at:at] = pam_block(c).rstrip('\n').split('\n')
    _put_file(path, '\n'.join(lines), 0o644)
    _drop(pam_radius_conf_legacy())
    return 'SSH asks for a code from acme (pam_radius)'


def sshd_text(c):
    lines = ['# acme - Settings -> SSH server and notices. Changed there, not here: this',
             '# file is written whole each time.',
             'Port %d' % c['port'],
             'PermitRootLogin %s' % c['permit_root'],
             'PasswordAuthentication %s' % ('yes' if c['password'] else 'no'),
             # A code from acme is asked in a second prompt: keyboard-interactive.
             'KbdInteractiveAuthentication %s' % ('yes' if c['password'] or c.get('radius')
                                                  else 'no'),
             'PubkeyAuthentication yes',
             'MaxAuthTries %d' % c['tries']]
    if c.get('radius'):
        lines.append('UsePAM yes')
    if c['allow_users']:
        lines.append('AllowUsers %s' % ' '.join(c['allow_users']))
    lines.append('Banner %s' % (notice_paths()['banner'] if c['notice_ssh'] else 'none'))
    lines += sshd_key_and_code(c)
    return '\n'.join(lines) + '\n'


def sshd_key_and_code(c):
    """A key first, then the code (1.0.183) - for the accounts the code is
    asked of; the others as before. A Match block, last in this file: sshd
    (8.2 and later) ends it at the end of the file it is in - checked after
    writing (sshd_match_kept)."""
    if not (c.get('radius') and c.get('radius_with_key')):
        return []
    both = 'AuthenticationMethods publickey,keyboard-interactive'
    out = []
    users = list(c.get('radius_users') or [])
    if sshd_root_code_key_only(c):
        # Root with a key only, and the code asked of it too (1.0.191): sshd hands
        # PAM "\b\n\r\177INCORRECT" for whatever root types where root may not use
        # a password - every code was refused. For root alone: what it types
        # reaches PAM, a key and the code both needed, never a password alone.
        out += ['# Root: a key, then the code from acme - never a password alone',
                'Match User root', '    PermitRootLogin yes', '    PasswordAuthentication no',
                '    ' + both]
        users = [u for u in users if u != 'root']
        if c.get('radius_users') and not users:
            return out
    if users:
        return out + ['# A key, then the code from acme - these accounts only',
                      'Match User %s' % ','.join(users), '    ' + both]
    if c.get('radius_root') and not out:
        return ['# A key, then the code from acme', both]
    return out + ['# A key, then the code from acme%s' % ('' if out else ' - root as before'),
                  'Match User *,!root', '    ' + both]


def sshd_root_code_key_only(c):
    """The code asked of root, root signing in with a key only, a key then the code."""
    if not (c.get('radius') and c.get('radius_with_key')) or c.get('permit_root') != 'prohibit-password':
        return False
    users = c.get('radius_users') or []
    return 'root' in users if users else bool(c.get('radius_root'))


def sshd_match_kept():
    """'' where every setting but AuthenticationMethods is the same for root
    and for anybody else - acme's Match did not reach into the system's own
    lines; else what differs."""
    def t(user):
        got = subprocess.run([SSHD_BIN, '-T', '-f', sshd_conf_path(), '-C',
                              'user=%s,host=localhost,addr=127.0.0.1' % user],
                             capture_output=True, text=True)
        return {l.split(' ', 1)[0]: l for l in got.stdout.split('\n') if l.strip()}, got.returncode
    a, ra = t('root')
    b, rb = t('acme-nobody-check')
    if ra or rb:
        return 'sshd -T did not answer'
    # Root's own block (1.0.191) sets these two for it, on purpose.
    ours = ('authenticationmethods', 'permitrootlogin', 'passwordauthentication')
    diff = sorted(k for k in set(a) | set(b) if k not in ours and a.get(k) != b.get(k))
    return ', '.join(diff[:5])


def sshd_selinux_port(port):
    """A port other than 22 let through by SELinux, where it is enforcing."""
    if port == 22 or not shutil.which('getenforce'):
        return ''
    mode = subprocess.run(['getenforce'], capture_output=True, text=True).stdout.strip()
    if mode != 'Enforcing':
        return ''
    if not shutil.which('semanage'):
        raise Refused('SELinux keeps sshd to port 22 and semanage is not on this machine '
                      '(dnf install policycoreutils-python-utils)')
    got = subprocess.run(['semanage', 'port', '-a', '-t', 'ssh_port_t', '-p', 'tcp', str(port)],
                         capture_output=True, text=True)
    if got.returncode != 0 and 'already defined' in (got.stderr or ''):
        # Defined already - for sshd, or for another service (1.0.51): 8443 is http_port_t, and
        # sshd, told it may, could not bind it after the reload and went away.
        owner = sshd_port_type(port)
        if owner and owner != 'ssh_port_t':
            raise Refused('SELinux gives port %d to %s - sshd could not take it; choose another '
                          'port' % (port, owner))
    elif got.returncode != 0:
        got = subprocess.run(['semanage', 'port', '-m', '-t', 'ssh_port_t', '-p', 'tcp',
                              str(port)], capture_output=True, text=True)
        if got.returncode != 0:
            raise Refused('semanage: %s' % (got.stderr or got.stdout).strip()[-200:])
    return 'SELinux lets sshd use port %d' % port


def sshd_port_type(port):
    """The SELinux type that holds a TCP port (semanage port -l), '' when none or not known."""
    got = subprocess.run(['semanage', 'port', '-l'], capture_output=True, text=True)
    if got.returncode != 0:
        return ''
    found = ''
    for line in (got.stdout or '').splitlines():
        w = line.split(None, 2)
        if len(w) < 3 or w[1] != 'tcp':
            continue
        for part in w[2].replace(' ', '').split(','):
            try:
                lo, _, hi = part.partition('-')
                lo, hi = int(lo), int(hi or lo)
            except ValueError:
                continue
            if lo <= port <= hi:
                if w[0] == 'ssh_port_t':
                    return 'ssh_port_t'
                found = found or w[0]
    return found


def sshd_reload():
    if NO_SERVICES:
        return
    for unit in ('sshd', 'ssh'):
        got = subprocess.run(['systemctl', 'reload-or-restart', unit], capture_output=True,
                             text=True)
        if got.returncode == 0:
            return
    raise Refused('sshd could not be reloaded: %s' % (got.stderr or '').strip()[-200:])


def sshd_trial_read():
    try:
        return json.loads(_read_or(SSHD_STATE) or '{}')
    except ValueError:
        return {}


def sshd_put_back(why='not kept in time'):
    """What was there before the change on trial, back."""
    t = sshd_trial_read()
    if not t:
        return False
    drop = os.path.join(SSH_DIR, SSHD_DROPIN)
    if t.get('dropin') is None:
        _drop(drop)
    else:
        _put_file(drop, t['dropin'], 0o600)
    for where in ('issue', 'motd'):
        notice_set(where, None)
        if t.get(where) is not None:
            notice_set(where, t[where])
    banner = notice_paths()['banner']
    if t.get('banner') is None:
        _drop(banner)
    else:
        _put_file(banner, t['banner'])
    if 'pam' in t:
        if t['pam'] is not None:
            _put_file(pam_sshd_path(), t['pam'], 0o644)
        if t.get('pamconf') is None:
            _drop(pam_radius_conf_path())
        else:
            _put_file(pam_radius_conf_path(), t['pamconf'], 0o600)
    try:
        sshd_reload()
    except Refused:
        pass
    _drop(SSHD_STATE)
    write_here('sshd-back.json', json.dumps({'at': time.time(), 'hash': t.get('hash'),
                                             'why': why}))
    return True


def sshd_arm(minutes, ident):
    """The timer that puts it back: systemd's own, not this helper's."""
    if NO_SERVICES or not minutes:
        return ''
    unit = 'acme-sshd-back-%s' % ident
    me = os.path.abspath(__file__)
    run(['systemd-run', '--on-active=%ds' % (int(minutes) * 60), '--unit', unit,
         sys.executable, '-I', me, '--sshd-back'], 'systemd-run')
    return unit


def sshd_disarm(t):
    unit = (t or {}).get('unit')
    if unit and not NO_SERVICES:
        subprocess.run(['systemctl', 'stop', unit + '.timer'], capture_output=True)


def sshd_apply_files(c, r, drop, now_dropin, paths, before):
    """The files of one change put in and sshd reloaded - what sshd_do undoes
    whole when anything of it fails (1.0.209)."""
    said = []
    if c['manage']:
        text = sshd_text(c)
        if c['notice_ssh']:
            _put_file(paths['banner'], c['notice'].rstrip() + '\n')
        _put_file(drop, text, 0o600)
        got = subprocess.run([SSHD_BIN, '-t', '-f', sshd_conf_path()], capture_output=True,
                             text=True)
        if got.returncode != 0:
            if now_dropin is None:
                _drop(drop)
            else:
                _put_file(drop, now_dropin, 0o600)
            raise Refused('sshd does not take it, so it is as it was: %s'
                          % (got.stderr or got.stdout).strip()[-300:])
        if c.get('radius_with_key'):
            drift = sshd_match_kept()
            if drift:
                if now_dropin is None:
                    _drop(drop)
                else:
                    _put_file(drop, now_dropin, 0o600)
                raise Refused('this sshd lets a Match of a file it includes reach its own '
                              'settings (%s) - a key and the code cannot be set here; it is '
                              'as it was' % drift)
        s = sshd_selinux_port(c['port'])
        if s:
            said.append(s)
        try:
            w = pam_set(c, r.get('radius_secret'), r.get('radius_port'))
        except Refused:
            if now_dropin is None:
                _drop(drop)
            else:
                _put_file(drop, now_dropin, 0o600)
            raise
        if w:
            said.append(w)
    else:
        if before['dropin'] is not None or os.path.exists(drop):
            _drop(drop)
        pam_set({'radius': False}, '', 0)
    notice_set('issue', c['notice'] if c['notice_console'] else None)
    notice_set('motd', c['notice'] if c['notice_motd'] else None)
    if not (c['manage'] and c['notice_ssh']):
        _drop(paths['banner'])
    sshd_reload()
    return said


def sshd_do(r):
    do = r.get('do')
    if do == 'apply':
        c = sshd_checked(r.get('conf'))
        trial = max(0, min(60, int(r.get('trial_min') or 0)))
        keys = root_keys_count()
        if c['manage']:
            if not sshd_reads_dropins():
                raise Refused('this sshd does not read sshd_config.d (OpenSSH before 8.2, or an '
                              'Include taken out of %s) - set it there by hand' % sshd_conf_path())
            if c['permit_root'] != 'no' and not c['password'] and not keys and \
                    not r.get('no_keys_ok'):
                raise Refused('root has no SSH key here, and passwords would be off: nobody would '
                              'reach this machine as root over SSH - add a key first')
            if c['permit_root'] == 'prohibit-password' and not keys and not r.get('no_keys_ok'):
                raise Refused('root may sign in only with a key and has none here - add a key '
                              'first')
            # AllowUsers naming nobody who is here (1.0.44): sshd -t takes it, and nobody signs in.
            if c['allow_users']:
                import pwd

                def there(u):
                    u = u.split('@', 1)[0]
                    if any(ch in u for ch in '*?'):
                        return True
                    try:
                        pwd.getpwnam(u)
                        return True
                    except KeyError:
                        return False
                if not any(there(u) for u in c['allow_users']):
                    raise Refused('none of AllowUsers (%s) is an account of this machine: nobody '
                                  'would sign in over SSH' % ', '.join(c['allow_users'])[:200])
        old = sshd_trial_read()
        # A change on trial changed again: one timer, the first state - its timer
        # stopped only once the new change is in (1.0.205). Stopped before it,
        # a change sshd refused left the one on trial with nothing to put it back.
        drop = os.path.join(SSH_DIR, SSHD_DROPIN)
        now_dropin = _read_or(drop)     # what this change, refused, goes back to
        paths = notice_paths()
        before = old or {'dropin': _read_or(drop), 'banner': _read_or(paths['banner']),
                         'issue': None, 'motd': None, 'pam': _read_or(pam_sshd_path()),
                         'pamconf': _read_or(pam_radius_conf_path())}
        if not old:
            for where in ('issue', 'motd'):
                cur = _read_or(paths[where])
                whole = os.path.basename(paths[where]) in ('issue', 'motd')
                if cur is not None and (not whole or cur.startswith(NOTICE_MARK.strip())):
                    before[where] = cur.split('\n', 1)[1] if whole else cur
        # Every file as it is now, put back on any failure (1.0.209): only sshd's
        # refusal was undone - a package that did not install, a notice that could
        # not be written or a reload that failed left the drop-in and PAM changed,
        # with no trial and no timer to put them back.
        entry = {pth: _read_or(pth) for pth in (drop, paths['banner'], paths['issue'],
                                                paths['motd'], pam_sshd_path(),
                                                pam_radius_conf_path())}
        ident = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:12] or 'x'
        new_unit = ''
        try:
            # The timer that puts it back armed first (otp 1.0.234): armed after the change, a
            # timer that could not be made left the change in with nothing to undo it - and
            # the one before already stopped.
            if trial and c['manage']:
                new_unit = sshd_arm(trial, ident)
                _put_file(SSHD_STATE, json.dumps(dict(
                    before, hash=str(r.get('hash') or '')[:64], until=time.time() + trial * 60,
                    unit=new_unit)), 0o600)
            said = sshd_apply_files(c, r, drop, now_dropin, paths, before)
        except BaseException:
            for pth, was in entry.items():
                try:
                    if was is None:
                        _drop(pth)
                    else:
                        _put_file(pth, was, 0o600 if pth in (drop, pam_radius_conf_path())
                                  else 0o644)
                except Exception:                       # noqa: BLE001
                    pass
            try:
                sshd_reload()
            except Exception:                           # noqa: BLE001
                pass
            if new_unit:
                sshd_disarm({'unit': new_unit})
            try:
                if old:
                    _put_file(SSHD_STATE, json.dumps(old), 0o600)
                else:
                    _drop(SSHD_STATE)
            except Exception:                           # noqa: BLE001
                pass
            raise
        if old and old.get('unit') != new_unit:
            sshd_disarm(old)
        if not (trial and c['manage']):
            _drop(SSHD_STATE)
        said.append('sshd reloaded')
    elif do == 'keep':
        t = sshd_trial_read()
        if t:
            sshd_disarm(t)
            _drop(SSHD_STATE)
    elif do == 'back':
        sshd_put_back(str(r.get('why') or 'asked to go back'))
    elif do == 'pamconf':
        # The gate's secret and port, nothing else (1.0.181): only where our
        # block is in sshd's PAM.
        text = _read_or(pam_sshd_path()) or ''
        if PAM_BEGIN in text:
            pam_radius_conf_write(r.get('radius_secret'), r.get('radius_port'))
            # A block from before 1.0.188: skip_passwd put in its pam_radius line.
            fixed = pam_skip_passwd(text)
            # And one from before 1.0.44: the secret's file where root alone writes now.
            fixed = fixed.replace('conf=%s ' % pam_radius_conf_legacy(),
                                  'conf=%s ' % pam_radius_conf_path())
            if fixed != text:
                _put_file(pam_sshd_path(), fixed, 0o644)
            _drop(pam_radius_conf_legacy())     # once the block names the new one
    elif do != 'read':
        raise Refused('read, apply, keep, back or pamconf')
    v = sshd_values()
    t = sshd_trial_read()
    return {'values': v, 'there': os.path.exists(SSHD_BIN), 'dropins': sshd_reads_dropins(),
            'dropin': _read_or(os.path.join(SSH_DIR, SSHD_DROPIN)), 'keys': root_keys_count(),
            'trial': {'hash': t.get('hash'), 'until': t.get('until')} if t else {},
            'paths': notice_paths(),
            'radius': {'module': bool(pam_radius_module()),
                       'pam': PAM_BEGIN in (_read_or(pam_sshd_path()) or ''),
                       'skip_passwd': pam_skip_passwd(_read_or(pam_sshd_path()) or '') ==
                       (_read_or(pam_sshd_path()) or ''),
                       'conf': os.path.exists(pam_radius_conf_path()),
                       'fp': pam_radius_conf_fp()},
            'selinux': subprocess.run(['getenforce'], capture_output=True, text=True).stdout.strip()
            if shutil.which('getenforce') else ''}


def sshd_part():
    d = web_fd()
    try:
        raw = read_req(SSHD_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(SSHD_ASK, d)
        return
    drop_ask(SSHD_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = sshd_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(SSHD_FILE, json.dumps(out))


# ---- the journal and the logs (1.0.166) ------------------------------------------------
# Asked with logs.ask by the daemon of this node: how much systemd's journal
# may take and for how long (journald.conf.d/00-acme.conf, journald restarted
# only when that file changed), and how many files of /var/log/acme logrotate
# keeps and how big one may grow (/etc/logrotate.d/acme, the two lines only).
# Answered with what the journal takes now.
LOGS_ASK, LOGS_ANS = 'logs.ask', 'logs.ans'
JOURNAL_DROPIN = 'systemd/journald.conf.d/00-acme.conf'
LOGROTATE_ACME = 'logrotate.d/acme'


def _int_in(r, key, lo, hi):
    try:
        v = int(r.get(key) or 0)
    except (TypeError, ValueError):
        raise Refused('%s: a whole number' % key)
    if not lo <= v <= hi:
        raise Refused('%s: %d to %d' % (key, lo, hi))
    return v


def journal_use():
    if not shutil.which('journalctl'):
        return None
    try:
        got = subprocess.run(['journalctl', '--disk-usage'], capture_output=True, text=True,
                             timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r'take up ([0-9.]+)([BKMGT])', got.stdout + got.stderr)
    if not m:
        return None
    return int(float(m.group(1)) * {'B': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30,
                                    'T': 1 << 40}[m.group(2)])


def logs_do(r):
    mb = _int_in(r, 'journal_mb', 0, 100000)
    days = _int_in(r, 'journal_days', 0, 3650)
    keep = _int_in(r, 'keep', 1, 3650)
    max_mb = _int_in(r, 'max_mb', 1, 100000)
    said = []
    path = os.path.join(ETC_DIR, JOURNAL_DROPIN)
    before = _read_or(path)
    if mb or days:
        text = ('# Written by acme (Settings - Disks and logs); changed there, not here.\n'
                '[Journal]\n' + ('SystemMaxUse=%dM\n' % mb if mb else '') +
                ('MaxRetentionSec=%dday\n' % days if days else ''))
        if before != text:
            _put_file(path, text)
            said.append('the journal: %s' % ', '.join(
                ([('at most %d MB' % mb)] if mb else []) + ([('%d days' % days)] if days else [])))
    elif before is not None:
        _drop(path)
        said.append('the journal: as the system has it')
    changed = (_read_or(path) != before)
    if changed and not NO_SERVICES and shutil.which('systemctl'):
        got = subprocess.run(['systemctl', 'restart', 'systemd-journald'], capture_output=True,
                             text=True, timeout=60)
        if got.returncode != 0:
            said.append('systemd-journald did not restart: %s' % (got.stderr or '').strip()[-200:])
    lr = os.path.join(ETC_DIR, LOGROTATE_ACME)
    text = _read_or(lr)
    if text is None:
        said.append('%s is not there - acme\'s logs are not rotated' % lr)
    else:
        new = re.sub(r'(?m)^(\s*)rotate\s+\d+\s*$', r'\g<1>rotate %d' % keep, text)
        new = re.sub(r'(?m)^(\s*)maxsize\s+\d+[kMG]?\s*$', r'\g<1>maxsize %dM' % max_mb, new)
        if new != text:
            _put_file(lr, new)
            said.append('acme\'s logs: %d kept, %d MB each at most' % (keep, max_mb))
    return {'journal_use': journal_use(), 'journal_conf': _read_or(path) or '',
            'rotate_conf': '\n'.join(x.strip() for x in (_read_or(lr) or '').splitlines()
                                     if re.match(r'\s*(rotate|maxsize)\b', x)),
            'said': said}


def logs_part():
    d = web_fd()
    try:
        raw = read_req(LOGS_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(LOGS_ASK, d)
        return
    drop_ask(LOGS_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict) or r.get('do') != 'apply':
            raise Refused('apply only')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = logs_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(LOGS_ANS, json.dumps(out))


# ---- updates of the operating system (1.0.158) ------------------------------------------
# Asked with osup.ask, answered at once; the work itself - minutes of dnf or
# apt - runs as a unit of its own (systemd-run), so this oneshot service ends
# and the other asks are served meanwhile. Its progress and its last lines go
# into osup.json, every second or so.
OSUP_ASK = 'osup.ask'
OSUP_ANS = 'osup.ans'
OSUP_FILE = 'osup.json'
OSUP_LOCK = os.environ.get('ACME_OSUP_LOCK', '/run/acme-osup.lock')
OSUP_PM = os.environ.get('ACME_OSUP_PM', '')          # tests: a fake package manager
# The proxy dnf and apt go through (1.0.166): handed over in osup.ask, kept
# here for the job, readable by root only, never on a command line.
OSUP_PROXY = os.environ.get('ACME_OSUP_PROXY', '/run/acme-osup-proxy.json')


def osup_proxy_keep(r):
    url = str(r.get('proxy') or '').strip()
    if url and not re.match(r'^https?://[^\s]+\Z', url):
        raise Refused('the proxy is not an http:// address')
    no = ','.join(w for w in re.split(r'[\s,;]+', re.sub(r'[^A-Za-z0-9.*:/\[\],;\s_-]', '',
                                                          str(r.get('proxy_no') or ''))) if w)
    if not url:
        _drop(OSUP_PROXY)
        return
    fd = os.open(OSUP_PROXY + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps({'url': url, 'no': no}))
    os.replace(OSUP_PROXY + '.new', OSUP_PROXY)


def osup_proxy_env(env):
    try:
        got = json.loads(_read_or(OSUP_PROXY) or '{}')
    except ValueError:
        got = {}
    if got.get('url'):
        for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
            env[k] = got['url']
        if got.get('no'):
            env['no_proxy'] = env['NO_PROXY'] = got['no']
    return env


def osup_pm():
    if OSUP_PM:
        return 'fake'
    if shutil.which('dnf'):
        return 'dnf'
    if shutil.which('apt-get'):
        return 'apt'
    return ''


def osup_running():
    import fcntl
    try:
        fd = os.open(OSUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def osup_launch(ident, kind, security=False):
    if osup_running():
        raise Refused('an update or a look for updates is going on already')
    if not osup_pm():
        raise Refused('neither dnf nor apt-get is on this machine')
    me = os.path.abspath(__file__)
    argv = [sys.executable, '-I', me, '--os-job', ident, kind] + (['security'] if security else [])
    if (shutil.which('systemd-run') and not NO_SERVICES and os.path.isdir('/run/systemd/system')):
        got = subprocess.run(['systemd-run', '--unit', 'acme-os-%s-%s' % (kind, ident[:12]),
                              '--collect', '--quiet', '--property', 'TimeoutStopSec=30min'] + argv,
                             capture_output=True, text=True, timeout=30)
        if got.returncode != 0:
            raise Refused('systemd-run: %s' % (got.stderr or got.stdout).strip()[-200:])
        return
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)


def osup_part():
    d = web_fd()
    try:
        raw = read_req(OSUP_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(OSUP_ASK, d)
        return
    drop_ask(OSUP_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        kind = r.get('kind')
        if r.get('do') != 'run' or kind not in ('check', 'upgrade'):
            raise Refused('run: check or upgrade')
        osup_proxy_keep(r)
        osup_launch(out['id'], kind, bool(r.get('security')) and kind == 'upgrade')
        out['ok'] = True
        out['data'] = {'started': kind, 'pm': osup_pm(), 'security': bool(r.get('security'))}
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(OSUP_ANS, json.dumps(out))


# The packages a restart is needed for once they are updated, as dnf
# needs-restarting -r and Debian's reboot-required name them (1.0.159).
REBOOT_PKGS = {'kernel', 'kernel-core', 'kernel-rt', 'kernel-rt-core', 'kernel-modules',
               'kernel-uek', 'glibc', 'linux-firmware', 'systemd', 'dbus', 'dbus-broker',
               'dbus-daemon', 'microcode_ctl', 'zlib', 'zlib-ng-compat', 'libc6', 'linux-base',
               'intel-microcode', 'amd64-microcode'}


def reboot_for(packages):
    """Which of the packages waiting want a restart once updated."""
    out = []
    for p in packages:
        name = str(p).split()[0] if str(p).split() else ''
        if re.search(r'\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$', name):
            name = name.rsplit('.', 1)[0]
        if name in REBOOT_PKGS or name.startswith(('linux-image', 'kernel-core-', 'linux-modules')):
            out.append(name)
    return sorted(set(out))


def reboot_now(pm, env, say=None):
    """Whether this machine waits for a restart already."""
    if pm == 'fake':
        return subprocess.run([OSUP_PM, 'needs-restart'], stdout=subprocess.DEVNULL).returncode == 1
    if pm == 'dnf':
        nr = subprocess.run(['dnf', 'needs-restarting', '-r'], capture_output=True,
                            text=True, env=env, timeout=300)
        if nr.returncode == 1 and say:
            say(nr.stdout.strip().splitlines()[0] if nr.stdout.strip() else 'a restart is needed')
        return nr.returncode == 1
    return os.path.exists('/var/run/reboot-required')


def osup_job(ident, kind, security=False):
    """The work itself, as root, in a process of its own."""
    import fcntl
    fd = os.open(OSUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 1
    state = {'id': ident, 'kind': kind, 'state': 'running', 'pct': 1, 'lines': [],
             'began': time.time(), 'at': time.time(), 'packages': [], 'reboot': False,
             'pm': osup_pm(), 'phase': 'starting'}
    last = [0.0]

    def put(force=False):
        state['at'] = time.time()
        if force or time.time() - last[0] > 0.8:
            last[0] = time.time()
            state['lines'] = state['lines'][-400:]
            write_here(OSUP_FILE, json.dumps(state))

    def say(line):
        line = line.rstrip()
        if line:
            state['lines'].append(line[:300])
        put()

    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'DEBIAN_FRONTEND': 'noninteractive', 'HOME': '/root'}
    osup_proxy_env(env)

    def stream(cmd, on_line=None, ok=(0,)):
        say('$ ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             stdin=subprocess.DEVNULL, text=True, bufsize=1)
        for ln in p.stdout:
            say(ln)
            if on_line:
                on_line(ln)
        rc = p.wait()
        if rc not in ok:
            raise Refused('%s ended with %d' % (cmd[0], rc))
        return rc

    pm = state['pm']
    try:
        put(True)
        if kind == 'check':
            state['phase'] = 'asking for what is new'
            pk = []
            if pm == 'fake':
                stream([OSUP_PM, 'check'], lambda ln: pk.append(ln.strip())
                       if ln.strip() and not ln.startswith('#') else None)
            elif pm == 'dnf':
                rc_out = []
                stream(['dnf', '-q', '--refresh', 'check-update'], rc_out.append, ok=(0, 100))
                for ln in rc_out:
                    parts = ln.split()
                    if len(parts) >= 3 and '.' in parts[0] and not ln.startswith(' '):
                        pk.append('%s %s' % (parts[0], parts[1]))
                state['security'] = 0
                sec = subprocess.run(['dnf', '-q', 'updateinfo', 'list', '--security'],
                                     capture_output=True, text=True, env=env, timeout=300)
                state['security'] = len([x for x in sec.stdout.splitlines() if x.strip()])
            else:
                stream(['apt-get', 'update'])
                got = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True,
                                     text=True, env=env, timeout=300)
                for ln in got.stdout.splitlines():
                    if '/' in ln and '[upgradable' in ln:
                        name = ln.split('/', 1)[0]
                        ver = ln.split()[1] if len(ln.split()) > 1 else ''
                        pk.append('%s %s' % (name, ver))
            state['packages'] = pk[:1000]
            state['count'] = len(pk)
            # Whether the update will need a restart, told before it is made.
            state['phase'] = 'whether a restart is needed'
            state['reboot_why'] = reboot_for(pk)
            state['reboot_after'] = bool(state['reboot_why'])
            try:
                state['reboot_now'] = reboot_now(pm, env)
            except (OSError, subprocess.SubprocessError):
                state['reboot_now'] = False
            if state['reboot_now']:
                say('a restart is needed already, before any update')
            if state['reboot_why']:
                say('a restart will be needed after the update: %s' % ', '.join(state['reboot_why']))
            state['pct'] = 100
        else:
            seen = {'total': 0, 'done': 0}

            def count(ln):
                m = re.search(r'\b(\d+)/(\d+)\s*$', ln)
                if pm in ('dnf', 'fake') and m and re.search(
                        r'(Upgrading|Installing|Cleanup|Verifying|Running scriptlet|Erasing|'
                        r'Reinstalling|Downgrading|Obsoleting)\s*:', ln):
                    total = int(m.group(2)) * 2          # each one upgraded and then verified
                    seen['total'] = max(seen['total'], total)
                    seen['done'] = min(seen['total'], seen['done'] + 1)
                    state['phase'] = 'putting the packages in'
                if pm == 'dnf' and ln.startswith('Downloading Packages'):
                    state['phase'] = 'downloading'
                    state['pct'] = max(state['pct'], 8)
                if pm == 'apt':
                    m2 = re.match(r'^(\d+) upgraded, (\d+) newly installed', ln)
                    if m2:
                        seen['total'] = (int(m2.group(1)) + int(m2.group(2))) * 2
                    if ln.startswith(('Unpacking ', 'Setting up ')):
                        seen['done'] += 1
                        state['phase'] = 'putting the packages in'
                    if ln.startswith('Get:'):
                        state['phase'] = 'downloading'
                        state['pct'] = max(state['pct'], 8)
                if seen['total']:
                    state['pct'] = max(state['pct'], min(97, 10 + int(87 * seen['done'] /
                                                                      seen['total'])))
            state['phase'] = 'asking for what is new'
            # Only the security updates where asked (1.0.164): dnf's own
            # --security, unattended-upgrade on apt (it takes the security
            # sources only, as Debian and Ubuntu set it up).
            state['security_only'] = bool(security)
            if pm == 'fake':
                stream([OSUP_PM, 'upgrade'] + (['security'] if security else []), count)
            elif pm == 'dnf':
                stream(['dnf', '-y', '--refresh', 'upgrade'] + (['--security'] if security else []),
                       count)
            elif security:
                if not shutil.which('unattended-upgrade'):
                    raise Refused('only the security updates: unattended-upgrade is not on this '
                                  'machine (apt install unattended-upgrades)')
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['unattended-upgrade', '-v'], count)
            else:
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o',
                        'Dpkg::Options::=--force-confold', 'upgrade'], count)
            state['phase'] = 'whether a restart is needed'
            state['reboot'] = reboot_now(pm, env, say)
            state['pct'] = 100
        state['state'] = 'done'
        state['phase'] = 'done'
    except Refused as e:
        state.update(state='failed', said=str(e)[:300])
    except Exception as e:                              # noqa: BLE001
        state.update(state='failed', said='it broke: %s' % str(e)[:300])
    finally:
        put(True)
        os.close(fd)
    return 0


# ---- SELinux (as otp 1.0.233) -------------------------------------------------------------------
# Asked in selinux.ask by the daemon of this node, from the pages (Settings - High security)
# or `acme --selinux-check`: how it is - the mode, acme's module, the labels acme's files have,
# the booleans and ports acme needs, what SELinux refused since the machine started - and,
# when asked, the three steps: made ready and permissive, enforcing, permissive again.
# Nothing of it is done unless asked; a machine with SELinux disabled stays so.
SELINUX_ASK, SELINUX_FILE = 'selinux.ask', 'selinux.json'
SE_CONFIG = os.environ.get('ACME_SELINUX_CONFIG', '/etc/selinux/config')
SE_RELABEL = os.environ.get('ACME_SELINUX_RELABEL', '/.autorelabel')
SE_CMDLINE = os.environ.get('ACME_SELINUX_CMDLINE', '/proc/cmdline')
SE_MODULE = 'acme_server'
SE_CIL = os.environ.get('ACME_SELINUX_CIL', '/usr/local/lib/acme/acme_server.cil')
# What acme's files should be labelled; the label is the third field of the context.
SE_LABELS = (('/run/acme', 'httpd_var_run_t', 'the folder of the API token'),
             ('/run/acme/api-token', 'httpd_var_run_t', 'the API token the pages read'),
             ('/var/www/acme', 'httpd_sys_content_t', 'the pages'),
             ('/usr/libexec/keepalived/acme-vip-check', 'keepalived_unconfined_script_exec_t',
              'keepalived\'s check of this node'))
SE_BOOLEANS = ('httpd_can_network_connect', 'authlogin_radius')   # the second: SSH with a code
SE_PORT_TYPES = ('postgresql_port_t', 'mysqld_port_t', 'ssh_port_t', 'radius_port_t')
# The programs whose refusals are acme's business.
SE_DOMAINS = ('httpd_t', 'keepalived_t', 'keepalived_unconfined_script_t', 'sshd_t',
              'chronyd_t', 'postgresql_t', 'syslogd_t', 'logrotate_t', 'unconfined_service_t',
              'init_t')


SE_APPLIED = 'selinux-applied'      # when acme's needs were last put in (otp 1.0.234)


def _se_run(cmd, timeout=120, light=False, data=None):
    if not shutil.which(cmd[0]):
        return None
    if light:
        # The heavy ones (semanage loads the whole policy, ausearch reads the audit log since
        # the start) at the lowest priority (otp 1.0.234): run on every node every half hour, they
        # took a core for seconds beside RADIUS.
        if shutil.which('ionice'):
            cmd = ['ionice', '-c', '3'] + cmd
        if shutil.which('nice'):
            cmd = ['nice', '-n', '19'] + cmd
    try:
        return subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


# When acme's needs were put in, kept where only root writes (1.0.44): in the acme account's folder,
# a time in the future written there hid every refusal, and "enforce" passed its check.
SE_APPLIED_ROOT = os.path.join(NET_SNAP_DIR, SE_APPLIED)


def se_applied_at():
    try:
        fd = os.open(SE_APPLIED_ROOT, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            if os.fstat(f.fileno()).st_uid != 0:
                return 0.0
            at = float(json.loads(f.read() or '{}').get('at') or 0)
        return min(at, time.time())
    except (OSError, TypeError, ValueError, AttributeError):
        return 0.0


def se_auditd():
    """Whether what SELinux refuses is written down at all: auditd running."""
    fake = os.environ.get('ACME_SELINUX_AUDITD')            # tests
    if fake:
        return fake == 'active'
    got = _se_run(['systemctl', 'is-active', 'auditd'], 20)
    return got is None or (got.stdout or '').strip() == 'active'


def se_mode():
    got = _se_run(['getenforce'], 20)
    if got is None:
        return 'absent'                 # no SELinux on this machine at all (Debian, Ubuntu)
    return (got.stdout or '').strip() or 'Disabled'


def se_config():
    text = _read_or(SE_CONFIG) or ''
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\s*(SELINUX|SELINUXTYPE)\s*=\s*([A-Za-z0-9_-]+)\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return {'mode': out.get('SELINUX', ''), 'type': out.get('SELINUXTYPE', ''),
            'there': bool(text)}


def se_config_set(mode):
    """SELINUX= in /etc/selinux/config, the rest of the file as it is."""
    if mode not in ('permissive', 'enforcing'):
        raise Refused('permissive or enforcing')
    text = _read_or(SE_CONFIG)
    if text is None:
        raise Refused('%s is not there - is the SELinux policy installed? '
                      '(dnf install selinux-policy-targeted)' % SE_CONFIG)
    if re.search(r'(?m)^\s*SELINUX\s*=', text):
        new = re.sub(r'(?m)^(\s*)SELINUX\s*=.*$', r'\g<1>SELINUX=%s' % mode, text)
    else:
        new = text.rstrip('\n') + '\nSELINUX=%s\n' % mode
    if new != text:
        _put_file(SE_CONFIG, new)


def se_cmdline_off():
    """selinux=0 on the kernel's command line: the config alone does not switch it on."""
    return bool(re.search(r'(?:^|\s)selinux=0(?:\s|$)', _read_or(SE_CMDLINE) or ''))


def se_label(path):
    fake = os.environ.get('ACME_SELINUX_LABELS')         # tests: {path: label}
    if fake:
        try:
            return (json.load(open(fake)) or {}).get(path)
        except (OSError, ValueError):
            return None
    try:
        raw = os.getxattr(path, 'security.selinux', follow_symlinks=False)
    except (OSError, AttributeError):
        return None
    ctx = raw.decode('utf-8', 'replace').rstrip('\0')
    parts = ctx.split(':')
    return parts[2] if len(parts) >= 3 else None


def se_module_in():
    got = _se_run(['semodule', '-l'], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    return any(line.split()[:1] == [SE_MODULE] for line in got.stdout.splitlines())


def se_bool(name):
    got = _se_run(['getsebool', name], 20)
    if got is None or got.returncode != 0:
        return None
    return bool(re.search(r'-->\s*on\s*$', got.stdout.strip()))


def se_ports():
    """semanage port -l: {(type, proto): [(lo, hi), ...]}; None without semanage."""
    got = _se_run(['semanage', 'port', '-l'], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    out = {}
    for line in got.stdout.splitlines():
        m = re.match(r'^(\S+_port_t)\s+(tcp|udp|sctp|dccp)\s+(.+)$', line.strip())
        if not m:
            continue
        spans = []
        for p in m.group(3).split(','):
            p = p.strip()
            a, _, b = p.partition('-')
            try:
                spans.append((int(a), int(b or a)))
            except ValueError:
                continue
        out.setdefault((m.group(1), m.group(2)), []).extend(spans)
    return out


def se_port_has(ports, kind, proto, port):
    return any(lo <= port <= hi for lo, hi in (ports or {}).get((kind, proto), []))


def se_denials(since=0.0):
    """What SELinux refused since the machine started - or since acme's needs were last put
    in (otp 1.0.234: what was refused before that is what they put right) - for the programs acme
    works with."""
    got = _se_run(['ausearch', '-m', 'AVC,USER_AVC', '-ts', 'boot'], 120, light=True)
    if got is None:
        return {'tool': False, 'total': 0, 'groups': [], 'since': since}
    groups = {}
    lines = {}
    total = 0
    for line in (got.stdout or '').splitlines():
        if 'avc:' not in line or 'denied' not in line:
            continue
        when = re.search(r'msg=audit\((\d+)(?:\.\d+)?:', line)
        if since and when and int(when.group(1)) < since:
            continue
        perms = re.search(r'denied\s+\{([^}]*)\}', line)
        sc = re.search(r'scontext=(\S+)', line)
        tc = re.search(r'tcontext=(\S+)', line)
        cl = re.search(r'tclass=(\S+)', line)
        comm = re.search(r'comm=(\S+)', line)
        name = re.search(r'\bname=(\S+)', line)
        if not (perms and sc and tc and cl):
            continue
        st = (sc.group(1).split(':') + ['', '', ''])[2]
        tt = (tc.group(1).split(':') + ['', '', ''])[2]
        what = ' '.join(x for x in (comm.group(1) if comm else '', name.group(1) if name else '')
                        if x)
        if st not in SE_DOMAINS and 'acme' not in line:
            continue
        total += 1
        key = (st, tt, cl.group(1), perms.group(1).strip())
        lines[key] = line
        g = groups.setdefault(key, {'source': st, 'target': tt, 'class': cl.group(1),
                                    'perms': perms.group(1).strip(), 'count': 0, 'what': ''})
        g['count'] += 1
        g['what'] = what.replace('"', '')[:120] or g['what']
        g['permissive'] = 'permissive=1' in line
    # Refused once, allowed now (otp 1.0.238): a module or a boolean that came after it - an upgrade
    # with a newer acme_server - settles it without "Put in what acme needs" pressed again.
    settled = 0
    for key in se_allowed_now(lines):
        settled += groups[key]['count']
        total -= groups.pop(key)['count']
    out = sorted(groups.values(), key=lambda g: -g['count'])[:30]
    return {'tool': True, 'total': total, 'groups': out, 'since': since, 'settled': settled}


def se_allowed_now(lines):
    """Which of the refusals (one line for each kind) the policy loaded now allows, as audit2why
    tells: "would be allowed by active policy". Nothing when audit2why is not there, or says
    nothing plain - then they count, as until now."""
    if not lines:
        return []
    by_id = {}
    for key, line in lines.items():
        m = re.search(r'msg=audit\(([0-9.]+:\d+)\)', line)
        if m:
            by_id[m.group(1)] = key
    if not by_id:
        return []
    got = _se_run(['audit2why'], 300, light=True,
                  data=''.join(lines[k] + '\n' for k in by_id.values()))
    if got is None or got.returncode != 0:
        return []
    now = set()
    cur = None
    for line in (got.stdout or '').splitlines():
        m = re.search(r'msg=audit\(([0-9.]+:\d+)\)', line)
        if m and 'avc:' in line:
            cur = by_id.get(m.group(1))
            continue
        if cur is not None and 'would be allowed by active policy' in line:
            now.add(cur)
    return sorted(now)


def se_want_checked(r):
    """What the daemon says acme needs here: booleans and ports, checked against what may be."""
    bools = []
    for b in (r.get('booleans') or [])[:8]:
        if not isinstance(b, dict) or b.get('name') not in SE_BOOLEANS:
            raise Refused('a boolean acme does not set')
        bools.append({'name': b['name'], 'why': str(b.get('why') or '')[:120]})
    ports = []
    for p in (r.get('ports') or [])[:16]:
        if not isinstance(p, dict) or p.get('type') not in SE_PORT_TYPES or \
                p.get('proto') not in ('tcp', 'udp'):
            raise Refused('a port type acme does not set')
        try:
            n = int(p.get('port'))
        except (TypeError, ValueError):
            raise Refused('a port is a number')
        if not 1 <= n <= 65535:
            raise Refused('a port is 1 to 65535')
        # The gate for SSH with a code (as otp 1.0.181): UDP of 18129-18199 only, never
        # RADIUS's own ports or another service's.
        if p['type'] == 'radius_port_t' and not (p['proto'] == 'udp' and 18129 <= n <= 18199):
            raise Refused('radius_port_t is for the gate for SSH only: UDP 18129-18199')
        ports.append({'port': n, 'proto': p['proto'], 'type': p['type'],
                      'why': str(p.get('why') or '')[:120]})
    return bools, ports


def se_check(r):
    bools, ports = se_want_checked(r)
    mode = se_mode()
    conf = se_config()
    out = {'mode': mode, 'config': conf['mode'], 'policy': conf['type'],
           'relabel_pending': os.path.exists(SE_RELABEL), 'cmdline_off': se_cmdline_off(),
           'tools': {'semanage': bool(shutil.which('semanage')),
                     'ausearch': bool(shutil.which('ausearch')),
                     'semodule': bool(shutil.which('semodule'))},
           'module': None, 'labels': [], 'booleans': [], 'ports': [],
           'denials': {'tool': False, 'total': 0, 'groups': []}, 'problems': []}
    if mode == 'absent':
        out['ready'] = False
        return out
    on = mode in ('Enforcing', 'Permissive')
    out['module'] = se_module_in()
    for path, want, why in SE_LABELS:
        if not os.path.exists(path):
            continue
        got = se_label(path) if on else None
        out['labels'].append({'path': path, 'label': got, 'want': want, 'why': why,
                              'ok': (got == want) if on else None})
    for b in bools:
        v = se_bool(b['name']) if on else None
        out['booleans'].append(dict(b, on=v))
    known = se_ports() if on else None
    for p in ports:
        out['ports'].append(dict(p, labelled=(se_port_has(known, p['type'], p['proto'], p['port'])
                                             if known is not None else None)))
    if on:
        out['denials'] = se_denials(se_applied_at())
        out['auditd'] = se_auditd()
    probs = out['problems']
    if on:
        if out['module'] is False:
            probs.append('acme\'s module (%s) is not installed' % SE_MODULE)
        probs.extend('%s is labelled %s, not %s (%s)' % (x['path'], x['label'] or '?', x['want'],
                                                         x['why'])
                     for x in out['labels'] if x['ok'] is False)
        probs.extend('the boolean %s is off (%s)' % (x['name'], x['why'])
                     for x in out['booleans'] if x['on'] is False)
        probs.extend('port %d/%s is not labelled %s (%s)' % (x['port'], x['proto'], x['type'],
                                                             x['why'])
                     for x in out['ports'] if x['labelled'] is False)
        if known is None and ports:
            probs.append('semanage is not on this machine - the ports cannot be checked '
                         '(dnf install policycoreutils-python-utils)')
        if out['denials']['total']:
            probs.append(('SELinux refused %d thing(s) since acme\'s needs were put in'
                          if out['denials'].get('since') else
                          'SELinux refused %d thing(s) since the machine started')
                         % out['denials']['total'])
        if not out.get('auditd', True):
            # Nothing written down, nothing counted (otp 1.0.234): enforcing let through on no word.
            probs.append('auditd does not run - what SELinux refuses is not written down '
                         '(systemctl enable --now auditd)')
        if not out['denials']['tool']:
            probs.append('ausearch is not on this machine - what SELinux refused cannot be '
                         'read (dnf install audit)')
    out['ready'] = (mode == 'Permissive' and not probs)
    return out


def se_apply(bools, ports, said, mark=True):
    """acme's module, labels, booleans and ports - on a machine where SELinux is on. `mark`:
    when anything was changed, what SELinux refused before no longer counts."""
    changed = False
    # Put in when it is not there, or when it is not the one last put in (otp 1.0.234): a newer
    # module beside the program, which install.sh could not put in, went in here.
    inpol = _read_or(SE_CIL + '.in-policy')
    if os.path.exists(SE_CIL) and shutil.which('semodule') and (
            se_module_in() is not True or inpol != _read_or(SE_CIL)):
        got = _se_run(['semodule', '-i', SE_CIL], 300)
        if got is None or got.returncode != 0:
            raise Refused('semodule -i %s: %s' % (SE_CIL, ((got.stderr or got.stdout)
                                                           if got else '').strip()[-200:]))
        said.append('acme\'s module installed')
        changed = True
        try:
            shutil.copyfile(SE_CIL, SE_CIL + '.in-policy')
        except OSError:
            pass
    for b in bools:
        if se_bool(b['name']) is False:
            got = _se_run(['setsebool', '-P', b['name'], 'on'], 300)
            if got is None or got.returncode != 0:
                raise Refused('setsebool -P %s on: %s' % (b['name'], ((got.stderr or '') if got
                                                                      else '').strip()[-200:]))
            said.append('%s on' % b['name'])
            changed = True
    known = se_ports()
    for p in ports:
        if known is None:
            raise Refused('semanage is not on this machine (dnf install '
                          'policycoreutils-python-utils)')
        if se_port_has(known, p['type'], p['proto'], p['port']):
            continue
        got = _se_run(['semanage', 'port', '-a', '-t', p['type'], '-p', p['proto'],
                       str(p['port'])], 300)
        if got is not None and got.returncode != 0 and 'already defined' in (got.stderr or ''):
            # Never taken from the service it belongs to (otp 1.0.234): -m labelled it for acme's
            # need, and that service could not bind it at its next start.
            raise Refused('port %d/%s is another service\'s in the SELinux policy - choose '
                          'another port for it (%s)' % (p['port'], p['proto'], p['why']))
        if got is None or got.returncode != 0:
            raise Refused('semanage port %d/%s: %s' % (p['port'], p['proto'], ((got.stderr or '')
                                                       if got else '').strip()[-200:]))
        said.append('port %d/%s labelled %s' % (p['port'], p['proto'], p['type']))
        changed = True
    if shutil.which('restorecon'):
        got = _se_run(['restorecon', '-R', '-v'] + [x for x in ('/run/acme', '/var/www/acme',
                                                              '/usr/libexec/keepalived')
                                                  if os.path.exists(x)], 300)
        if got is not None and 'elabel' in (got.stdout or '') + (got.stderr or ''):
            said.append('acme\'s files labelled again')
            changed = True
    # From now on what is refused counts again (otp 1.0.234): what was refused before is what
    # this put right - a second restart was needed before enforcing could be switched on.
    # Only when something was changed, and never on the way to enforcing: what was refused
    # before that still counts there.
    if mark and changed:
        write_here(SE_APPLIED, json.dumps({'at': time.time()}))
        os.makedirs(NET_SNAP_DIR, mode=0o700, exist_ok=True)
        write_root(SE_APPLIED_ROOT, json.dumps({'at': time.time()}), 0o600)


def se_do(r):
    do = r.get('do')
    bools, ports = se_want_checked(r)
    said = []
    if do == 'check':
        return se_check(r)
    if do == 'report':
        # Read only (otp 1.0.236): left in the web folder for the daemon, the acme group's to read.
        node = re.sub(r'[^A-Za-z0-9._-]', '', str(r.get('node') or 'node'))[:60] or 'node'
        data = se_report_bytes(r, node)
        try:
            import grp
            gid = grp.getgrnam('acme').gr_gid
        except (KeyError, ImportError):
            gid = None
        se_report_here(data, SE_REPORT_FILE, gid)
        return {'report': SE_REPORT_FILE, 'bytes': len(data), 'at': time.time()}
    mode = se_mode()
    if mode == 'absent':
        raise Refused('there is no SELinux on this machine')
    if do == 'prepare':
        if mode == 'Enforcing':
            raise Refused('SELinux is enforcing already')
        se_config_set('permissive')
        said.append('%s: SELINUX=permissive' % SE_CONFIG)
        if mode == 'Disabled':
            # Every file labelled at the next start, before anything runs (minutes); the
            # booleans and ports are put in by this step again once it is permissive
            # ("Put in what acme needs").
            open(SE_RELABEL, 'a').close()
            said.append('the files are labelled at the next start of the machine')
            if se_cmdline_off() and shutil.which('grubby'):
                got = _se_run(['grubby', '--update-kernel', 'ALL', '--remove-args', 'selinux'],
                              120)
                if got is None or got.returncode != 0:
                    raise Refused('grubby: %s' % ((got.stderr or '') if got else '')[-200:])
                said.append('selinux=0 taken off the kernel\'s command line')
            elif se_cmdline_off():
                said.append('the kernel\'s command line has selinux=0: take it away '
                            '(grubby --update-kernel ALL --remove-args selinux)')
            if os.path.exists(SE_CIL) and shutil.which('semodule'):
                got = _se_run(['semodule', '-i', SE_CIL], 300)    # into the store; may not
                if got is not None and got.returncode == 0:       # work while disabled
                    said.append('acme\'s module installed')
            said.append('restart the machine - it comes up permissive: nothing is refused yet, '
                        'what would be is written down')
        else:
            se_apply(bools, ports, said)
    elif do == 'enforce':
        if mode != 'Permissive':
            raise Refused('SELinux is %s - it goes to enforcing from permissive only'
                          % mode.lower())
        se_apply(bools, ports, said, mark=False)
        c = se_check(r)
        if c['problems']:
            raise Refused('not yet: ' + '; '.join(c['problems'][:4]))
        got = _se_run(['setenforce', '1'], 60)
        if got is None or got.returncode != 0:
            raise Refused('setenforce 1: %s' % ((got.stderr or '') if got else '')[-200:])
        se_config_set('enforcing')
        said.append('SELinux is enforcing, and stays so after a restart')
    elif do == 'permissive':
        if mode == 'Disabled':
            raise Refused('SELinux is disabled - "prepare" makes it permissive')
        if mode == 'Enforcing':
            got = _se_run(['setenforce', '0'], 60)
            if got is None or got.returncode != 0:
                raise Refused('setenforce 0: %s' % ((got.stderr or '') if got else '')[-200:])
        se_config_set('permissive')
        said.append('SELinux is permissive, and stays so after a restart')
    else:
        raise Refused('check, prepare, enforce or permissive')
    out = se_check(r)
    out['said'] = said
    return out


# ---- what SELinux needs, gathered for whoever writes acme's module (otp 1.0.236) -------------------
SE_REPORT_FILE = 'selinux-report.tar.gz'
SE_REPORT_MOST = 2 * 1024 * 1024        # each part at most, before it is packed
SE_REPORT_PATHS = ('/run/acme', '/run/acme/api-token', '/var/lib/acme', '/var/lib/acme/web', '/etc/acme',
                   '/etc/acme/config.json', '/var/www/acme', '/usr/local/lib/acme', '/var/log/acme',
                   '/usr/libexec/keepalived/acme-vip-check', '/etc/nginx/certs', '/etc/nginx/conf.d',
                   '/etc/keepalived/keepalived.conf', '/etc/chrony.conf', '/etc/ssh/sshd_config.d',
                   '/etc/pam.d/sshd', '/run/php-fpm', '/var/lib/pgsql', '/etc/pki/rsyslog', '/etc/pki/acme')
SE_REPORT_COMMS = ('python', 'acme', 'nginx', 'php-fpm', 'keepalived', 'sshd', 'chronyd', 'postgres',
                   'postmaster', 'mariadbd', 'mysqld', 'rsyslogd', 'auditd', 'acme-vip-check')
SE_REPORT_PORT_TYPES = ('dns_port_t', 'ssh_port_t', 'http_port_t', 'postgresql_port_t',
                        'mysqld_port_t', 'syslogd_port_t', 'snmp_port_t', 'ntp_port_t',
                        'unreserved_port_t', 'vrrp_port_t', 'radius_port_t')


def _se_out(cmd, timeout=120, data=None, light=True):
    """A command's words for the report - what it said, or why it said nothing."""
    if not shutil.which(cmd[0]):
        return '(%s is not on this machine)\n' % cmd[0]
    if light:
        if shutil.which('ionice'):
            cmd = ['ionice', '-c', '3'] + cmd
        if shutil.which('nice'):
            cmd = ['nice', '-n', '19'] + cmd
    try:
        got = subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return '(%s: %s)\n' % (' '.join(cmd), e)
    text = (got.stdout or '') + (('\n--- stderr ---\n' + got.stderr) if got.stderr.strip() else '')
    return _se_cut(text)


def _se_cut(text):
    b = text.encode('utf-8', 'replace')
    if len(b) <= SE_REPORT_MOST:
        return text
    # The newest lines kept: the end of the audit log is what came last.
    return '(the first %d bytes left out - too long)\n' % (len(b) - SE_REPORT_MOST) + \
        b[-SE_REPORT_MOST:].decode('utf-8', 'replace')


def se_report_parts(r):
    """Every part of the report: {name: text}. Read only - nothing is changed."""
    parts = {}
    check = se_check(r)
    parts['check.json'] = json.dumps(check, indent=1, sort_keys=True)
    parts['acme.json'] = json.dumps({'facts': r.get('facts') or {}, 'want': {
        'booleans': r.get('booleans') or [], 'ports': r.get('ports') or []}}, indent=1, sort_keys=True)
    raw = _se_out(['ausearch', '-m', 'AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR', '-ts', 'boot'], 300)
    parts['avc-raw.txt'] = raw
    parts['avc.txt'] = _se_out(['ausearch', '-m', 'AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR',
                                '-ts', 'boot', '-i'], 300)
    if raw.startswith('('):
        parts['audit2why.txt'] = parts['audit2allow.te'] = raw
    else:
        parts['audit2why.txt'] = _se_out(['audit2why'], 300, data=raw)
        parts['audit2allow.te'] = _se_out(['audit2allow', '-m', 'acme_local'], 300, data=raw)
    sysw = []
    for name, cmd in (('os-release', ['cat', '/etc/os-release']), ('kernel', ['uname', '-a']),
                      ('started', ['uptime', '-s']), ('getenforce', ['getenforce']),
                      ('sestatus', ['sestatus', '-v']),
                      ('packages', ['rpm', '-q', 'selinux-policy', 'selinux-policy-targeted',
                                    'policycoreutils', 'policycoreutils-python-utils',
                                    'libselinux-utils', 'audit', 'nginx', 'php-fpm', 'keepalived',
                                    'openssh-server', 'chrony', 'postgresql-server']),
                      ('kernel command line', ['cat', SE_CMDLINE]),
                      ('selinux config', ['cat', SE_CONFIG]),
                      ('auditd', ['systemctl', 'is-active', 'auditd'])):
        sysw.append('==== %s\n%s' % (name, _se_out(cmd, 60, light=False)))
    parts['system.txt'] = '\n'.join(sysw)
    lab = []
    for p in SE_REPORT_PATHS:
        if os.path.lexists(p):
            lab.append(_se_out(['ls', '-Zd', p], 20, light=False).rstrip())
            if os.path.isdir(p):
                lab.append(_se_out(['ls', '-Za', p], 20, light=False).rstrip())
            lab.append('  policy says: ' + _se_out(['matchpathcon', p], 20, light=False).strip())
    parts['labels.txt'] = '\n'.join(lab) + '\n'
    ps = _se_out(['ps', '-eZo', 'label,user,pid,comm'], 60, light=False)
    keep = [x for x in ps.splitlines() if x.startswith('LABEL') or
            any(c in x for c in SE_REPORT_COMMS)]
    # Arguments cut to 200: what runs, not every word it was given.
    parts['processes.txt'] = '\n'.join(x[:200] for x in keep) + '\n'
    ports = _se_out(['semanage', 'port', '-l'], 300)
    parts['ports.txt'] = '==== labelled\n' + '\n'.join(
        x for x in ports.splitlines() if x.split()[:1] and x.split()[0] in SE_REPORT_PORT_TYPES) + \
        '\n\n==== listening\n' + _se_out(['ss', '-lntupZ'], 60, light=False)
    bools = _se_out(['getsebool', '-a'], 60, light=False)
    parts['booleans.txt'] = '\n'.join(x for x in bools.splitlines() if re.match(
        r'^(httpd_|authlogin_|nis_enabled|keepalived|daemons_|logging_|ssh|use_nfs|domain_can)',
        x)) + '\n'
    mods = _se_out(['semodule', '-l'], 300)
    parts['modules.txt'] = '==== acme\n' + '\n'.join(
        x for x in mods.splitlines() if 'acme' in x.lower()) + '\n\n==== %s\n%s\n==== in the policy\n%s\n' % (
        SE_CIL, _read_or(SE_CIL) or '(not there)', _read_or(SE_CIL + '.in-policy') or '(none put in yet)')
    parts['README.txt'] = (
        'acme - what SELinux says on this node, for whoever writes acme\'s module (acme_server).\n'
        'Made %s. Nothing was changed to make it.\n\n'
        'check.json      the card: mode, module, labels, booleans, ports, refusals\n'
        'avc*.txt        what SELinux refused since the machine started (raw and readable)\n'
        'audit2why.txt   why; audit2allow.te: what would allow it - a hint, not to be loaded\n'
        'labels.txt      the labels of acme\'s files and what the policy says they should be\n'
        'processes.txt   the domains the programs run in; ports.txt, booleans.txt, modules.txt\n'
        'system.txt      the system, the policy and the packages; acme.json: what acme uses here\n\n'
        'No password, key or token of acme is in it. The audit log holds the command lines of the\n'
        'programs refused something: acme never puts a secret on one - other programs on this\n'
        'machine may. Look through avc*.txt before sending it on.\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
    return parts


def se_report_bytes(r, top):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, text in se_report_parts(r).items():
            data = text.encode('utf-8', 'replace')
            info = tarfile.TarInfo('%s/%s' % (top, name))
            info.size = len(data)
            info.mtime = int(time.time())
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def se_report_here(data, name, gid=None):
    """The report into the web folder through its descriptor (1.0.44) - never a path through
    /var/lib/acme, whose web folder the acme account could swap for a link meanwhile."""
    d = web_fd()
    tmp = '.acme-selinux-%d' % os.getpid()
    try:
        os.unlink(tmp, dir_fd=d)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=d)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            if gid is not None:
                os.fchown(f.fileno(), 0, gid)
                os.fchmod(f.fileno(), 0o640)
        os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=d)
        except OSError:
            pass
        raise


def se_report_write(data, path, uid=0, gid=None):
    """Written whole and put in place, readable by root (and the acme group when asked)."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.acme-selinux-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o640 if gid is not None else 0o600)
            if gid is not None:
                os.fchown(f.fileno(), uid, gid)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def selinux_part():
    d = web_fd()
    try:
        raw = read_req(SELINUX_ASK, 16384)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_ask(SELINUX_ASK, d)
        return
    drop_ask(SELINUX_ASK, d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = se_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(SELINUX_FILE, json.dumps(out))


def se_report(c):
    """`acme --selinux-check`: what se_check found, for a person."""
    lines = ['SELinux: %s (config: %s%s)' % (c['mode'], c.get('config') or '?',
                                            ', %s' % c['policy'] if c.get('policy') else '')]
    if c['mode'] == 'absent':
        lines.append('  no SELinux on this machine - nothing to do')
        return '\n'.join(lines)
    if c.get('relabel_pending'):
        lines.append('  the files are labelled at the next start of the machine')
    if c.get('cmdline_off'):
        lines.append('  the kernel\'s command line has selinux=0')
    if c['mode'] == 'Disabled':
        lines.append('  disabled - acme runs as always; "Make it ready (permissive)" on the pages '
                     '(Settings - High security) makes it permissive at the next start')
        return '\n'.join(lines)
    lines.append('  module %s: %s' % (SE_MODULE, {True: 'installed', False: 'NOT installed',
                                                  None: '?'}[c['module']]))
    for x in c['labels']:
        lines.append('  %s %s: %s%s' % ('ok  ' if x['ok'] else 'FAIL', x['path'], x['label'] or '?',
                                        '' if x['ok'] else ' (want %s)' % x['want']))
    for x in c['booleans']:
        lines.append('  %s boolean %s: %s - %s' % ('ok  ' if x['on'] else 'FAIL', x['name'],
                                                   'on' if x['on'] else 'off', x['why']))
    for x in c['ports']:
        lines.append('  %s port %d/%s %s - %s' % ('ok  ' if x['labelled'] else 'FAIL', x['port'],
                                                 x['proto'], x['type'], x['why']))
    d = c['denials']
    lines.append('  refused since the start: %s' % (d['total'] if d['tool'] else
                                                    '? (ausearch is not there)'))
    if d.get('settled'):
        lines.append('  refused before, allowed now (not counted): %d' % d['settled'])
    for g in d['groups'][:15]:
        lines.append('    %4dx %s -> %s %s { %s } %s' % (g['count'], g['source'], g['target'],
                                                         g['class'], g['perms'], g['what']))
    lines.append('ready for enforcing' if c.get('ready') else
                 ('enforcing' if c['mode'] == 'Enforcing' and not c['problems'] else
                  'not ready: ' + '; '.join(c['problems'][:6]) if c['problems'] else ''))
    return '\n'.join(x for x in lines if x)


SLOW_PART_S = 3.0


def sshd_overdue():
    """A change of sshd on trial whose time is up and that nobody kept, put back (1.0.234):
    its timer, systemd's own, does not outlive a restart of the machine - and an admin locked
    out by the change restarts it. The trial was kept for good."""
    t = sshd_trial_read()
    try:
        until = float((t or {}).get('until') or 0)
    except (TypeError, ValueError):
        until = 0
    if until and time.time() > until + 30:
        sshd_put_back('not kept in time (its timer did not outlive a restart)')


def _serve_parts():
    return [(sshd_overdue, 'a change of sshd on trial'), (pglog_part, 'the PostgreSQL log'), (pgtls_part, 'the database link'),
            (dbmake_part, 'a database made'), (fw_read_part, 'the firewall as it is'),
            (net_part, 'the network'), (ntp_part, 'the time'),
            (console_part, 'the console at login'), (sshkeys_part, "root's SSH keys"),
            (users_part, 'the local users'),
            (osup_part, 'the updates of the system'), (sshd_part, 'the SSH server'),
            (logs_part, 'the journal and the logs'), (selinux_part, 'SELinux')]


def serve():
    d = web_fd()
    # Each part on its own, its time said in the journal when it is slow (1.0.23): a
    # page that waits on one ask waits for every part before it.
    for fn, what in _serve_parts():
        t0 = time.time()
        try:
            fn()
        except Exception as e:                          # noqa: BLE001
            print('acme_web.py: %s: %s' % (what, e), file=sys.stderr)
        took = time.time() - t0
        if took >= SLOW_PART_S:
            print('acme_web.py: %s took %.1f s' % (what, took), file=sys.stderr)
    try:
        os.replace('request.json', 'request.taken', src_dir_fd=d, dst_dir_fd=d)
    except FileNotFoundError:
        return 0
    except OSError:
        # request.taken a folder, or request.json one (1.0.94): both taken
        # away, not left to start this service over and over.
        drop_ask('request.taken', d)
        drop_ask('request.json', d)
        return 1
    last = status_read()
    out = {'at': time.time(), 'applied': last.get('applied') or {}, 'dh': last.get('dh') or {}}
    try:
        try:
            raw = json.loads(read_req('request.taken').decode('utf-8'))
        except ValueError as e:
            raise Refused('the request does not read: %s' % e)
        if isinstance(raw, dict):
            out.update(id=re.sub(r'[^A-Za-z0-9]', '', str(raw.get('id') or ''))[:32],
                       hash=re.sub(r'[^0-9a-f]', '', str(raw.get('hash') or ''))[:64])
        PROGRESS['id'] = str(out.get('id') or '')
        progress('checking what was asked', 1)
        r = checked(raw)
        out.update(id=r['id'], hash=r['hash'], vip_on=r['vip']['on'])
        said_n, dh = nginx_part(r, last)
        out['dh'] = dict(out['dh'], **dh)
        said_v, keep = vip_part(r, last.get('applied') or {})
        said_f, fw = fw_part(r['fw'])
        out.update(state='done', said=[s for s in said_n + said_v + said_f if s], applied=keep,
                   fw=fw, access=access_now())
    except Refused as e:
        out.update(state='failed', said=[str(e)])
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out.update(state='failed', said=['it broke: %s' % e])
    finally:
        for name in ('request.taken', 'progress.json'):
            try:
                os.unlink(name, dir_fd=d)
            except OSError:
                pass
    write_here('status.json', json.dumps(out))
    return 0


def main(argv):
    if argv[:1] == ['--status']:
        print(json.dumps({'keepalived': ka_ours(), 'nginx_vip': os.path.exists(NGINX_VIP),
                          'status': status_read()}))
        return 0
    if os.geteuid() != 0:
        print('acme_web.py: root only', file=sys.stderr)
        return 2
    if argv[:1] == ['--dbmake']:
        # As root by hand, or by a daemon that runs as root (1.0.210).
        print(json.dumps(dbmake_do(sys.stdin.read())))
        return 0
    if argv[:1] == ['--selinux-report'] and len(argv) >= 2:
        # `acme --selinux-report` (as otp 1.0.236): what acme needs and what came on stdin, into
        # a file.
        want = {}
        try:
            want = json.loads(sys.stdin.read(65536) or '{}')
        except ValueError:
            want = {}
        want = want if isinstance(want, dict) else {}
        out = argv[1]
        node = re.sub(r'[^A-Za-z0-9._-]', '', str(want.get('node') or 'node'))[:60] or 'node'
        try:
            data = se_report_bytes(want, node)
            se_report_write(data, out)
        except (Refused, OSError) as e:
            print('acme_web.py: %s' % e, file=sys.stderr)
            return 2
        print(out)
        return 0
    if argv[:1] == ['--selinux-do'] and len(argv) >= 2:
        # `acme --selinux prepare|apply|enforce|permissive` (as otp 1.0.236): one step here.
        want = {}
        try:
            want = json.loads(sys.stdin.read(65536) or '{}')
        except ValueError:
            want = {}
        do = {'apply': 'prepare'}.get(argv[1], argv[1])
        try:
            c = se_do(dict(want if isinstance(want, dict) else {}, do=do))
        except Refused as e:
            print('acme_web.py: %s' % e, file=sys.stderr)
            return 2
        said = c.pop('said', []) if isinstance(c, dict) else []
        print(json.dumps(c) if '--json' in argv else
              '\n'.join(['done: ' + x for x in said] + [se_report(c)]))
        return 0
    if argv[:1] == ['--selinux-check']:
        # `acme --selinux-check` (as otp 1.0.233): what acme needs here comes on stdin from the
        # acme command, as JSON; nothing is changed.
        want = {}
        if '--want-stdin' in argv:
            try:
                want = json.loads(sys.stdin.read(65536) or '{}')
            except ValueError:
                want = {}
        try:
            c = se_check(want if isinstance(want, dict) else {})
        except Refused as e:
            print('acme_web.py: %s' % e, file=sys.stderr)
            return 2
        print(json.dumps(c) if '--json' in argv else se_report(c))
        return 0 if (c['mode'] in ('absent', 'Disabled') or not c['problems']) else 1
    if argv[:1] == ['--sshd-back']:
        # The timer of a change of sshd on trial (1.0.163): not kept in time.
        sshd_put_back()
        return 0
    if argv[:1] == ['--pam-off']:
        # acme taken away (1.0.206): sshd's PAM no longer asks an acme that is not
        # there - every password and code over SSH was refused after an
        # uninstall - and no change on trial is left with a timer that runs
        # what is gone.
        said = pam_set({'radius': False}, '', 0)
        t = sshd_trial_read()
        if t:
            sshd_disarm(t)
            _drop(SSHD_STATE)
        print(said or 'sshd\'s PAM had nothing of acme in it')
        return 0
    if argv[:1] == ['--os-job'] and len(argv) >= 3 and argv[2] in ('check', 'upgrade'):
        return osup_job(re.sub(r'[^A-Za-z0-9]', '', argv[1])[:40], argv[2],
                        argv[3:4] == ['security'])
    return serve()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
