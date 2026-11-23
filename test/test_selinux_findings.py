"""What SELinux refuses, sorted by what puts it right (1.0.120, as fake-igd's kit).

    python3 test/test_selinux_findings.py

No SELinux needed: the root helper (deploy/acme_web.py) runs with a stand-in machine - getenforce,
setenforce, getsebool, setsebool, semanage, semodule, ausearch, audit2why, matchpathcon, restorecon -
that keeps its state (the mode, booleans, port types, modules, labels) and answers as the real tools
do; ausearch answers with fixtures in the raw form of the real one (records of an event, strings
hex-encoded where they hold a space or a byte that is not plain).

- the analysis: records of an event read together, hex decoded only for proctitle name path comm exe
  cwd (never a port), whole paths from PATH and CWD, USER_AVC and SELINUX_ERR; grouping; ids stable
  (a hash of what was refused); every kind - boolean, label, port, a rule of acme's, not for a
  button with each reason of the kit's lists, not acme's, allowed now (not counted);
- putting right by ids only: setsebool, restorecon, semanage port, acme's local module built and
  loaded (each rule optional) - under enforcing too; a request carrying anything but ids refused;
  a rule taken away (the last one takes the module out); put right noted, coming back when refused
  again after;
- the steps and the lock on enforcing while something fixable or not for a button is left;
- the report: every file of the kit's table, nothing secret of acme's in it;
- two nodes: each node's findings and fixes its own - an id of one never applied on the other, a
  fix asked of one done by that node's daemon and root only; one node at a time for the steps;
- the command line (look, fix ID / --all, rules --take-away, report, the old options as before),
  the API (ids only), "To be done by hand" and the alert's words;
- the module: every rule in an optional block, nnp_transition for the tools of acme.service, the
  keepalived check labelled; checked with secilc against a reference policy where one is given
  (ACME_SECILC=path/to/secilc ACME_REFPOLICY_CIL=folder of the policy's .cil files, optional
  ACME_SECILC_LD=LD_LIBRARY_PATH);
- the card in Chromium (Playwright): English and Czech (ACME_CS_EXTRA={English: Czech} merged into a
  copy of web/lang/cs.json while it is not merged), 1400 and 390 px, a read-only account, no error in
  the console, nothing wider than the window; screenshots into ACME_SHOTS.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-sefind-')
os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-a'))
with open(os.path.join(TMP, 'config.json'), 'w') as _f:
    json.dump({'api_port': 9861, 'db_password': 'Db-S3cret-4711', 'snmp_auth_pass': 'Snmp-S3cret-4711'}, _f)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def helper(snap):
    """The root helper of one machine: a module of its own, its own root folder."""
    os.environ['ACME_NET_SNAP_DIR'] = snap
    spec = importlib.util.spec_from_file_location('acme_web_sefind_%d' % len(snap), os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


W = helper(os.path.join(TMP, 'root-a'))
BOOT = int(time.time()) - 7200


def hexs(s):
    return s.encode('utf-8').hex().upper()


ACME_PT = hexs('/usr/local/lib/acme/python\0/usr/local/lib/acme/current/acme.py\0--daemon')
CTX = 'system_u:system_r:%s:s0'
OBJ = 'system_u:object_r:%s:s0'


def event(n, recs, ts=None):
    """One event as ausearch writes it (raw): '----', 'time->', and its records."""
    ts = ts or BOOT + n * 10
    mid = '%d.%03d:%d' % (ts, n % 1000, 1000 + n)
    out = ['----', 'time->%s' % time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(ts))]
    for typ, rest in recs:
        out.append('type=%s msg=audit(%s): %s' % (typ, mid, rest))
    return '\n'.join(out)


def sysc(comm, exe, src):
    return ('SYSCALL', 'arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7f a2=0 a3=0 items=1 ppid=1 '
                       'pid=4410 auid=4294967295 uid=990 gid=990 euid=990 suid=990 fsuid=990 egid=990 sgid=990 '
                       'fsgid=990 tty=(none) ses=4294967295 comm=%s exe=%s subj=%s key=(null)'
            % ('"%s"' % comm if ' ' not in comm else hexs(comm), '"%s"' % exe, CTX % src))


def path(name, obj, nametype='NORMAL', item=0):
    n = '"%s"' % name if re.match(r'^[\x21-\x7e]+$', name) and '"' not in name else hexs(name)
    return ('PATH', 'item=%d name=%s inode=1234 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=%s '
                    'nametype=%s cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0' % (item, n, OBJ % obj, nametype))


def cwd(d):
    return ('CWD', 'cwd=%s' % ('"%s"' % d if ' ' not in d else hexs(d)))


def proct(t):
    return ('PROCTITLE', 'proctitle=%s' % hexs(t))


# What SELinux refused on the stand-in machine A since it started: every kind of the kit's table.
FIX = {
    'nnp_chronyc': [[proct('/usr/local/lib/acme/python\0/usr/local/lib/acme/current/acme.py\0--daemon'),
                     sysc('acme-clock', '/usr/local/lib/acme/python3.14', 'unconfined_service_t'),
                     ('AVC', 'avc:  denied  { nnp_transition } for  pid=4410 comm="acme-clock" scontext=%s '
                             'tcontext=%s tclass=process2 permissive=1' % (CTX % 'unconfined_service_t', CTX % 'chronyc_t'))]] * 2,
    'label_core': [[proct('nginx: worker process'), cwd('/'), path('/var/www/acme/assets/core.js', 'default_t'),
                    sysc('nginx', '/usr/sbin/nginx', 'httpd_t'),
                    ('AVC', 'avc:  denied  { read } for  pid=900 comm="nginx" name="core.js" dev="dm-0" ino=1234 '
                            'scontext=%s tcontext=%s tclass=file permissive=1' % (CTX % 'httpd_t', OBJ % 'default_t'))]] * 2,
    'port_sshd': [[sysc('sshd', '/usr/sbin/sshd', 'sshd_t'),
                   ('AVC', 'avc:  denied  { name_bind } for  pid=1 comm="sshd" src=2222 scontext=%s tcontext=%s '
                           'tclass=tcp_socket permissive=1' % (CTX % 'sshd_t', OBJ % 'unreserved_port_t'))]],
    'bool_api': [[sysc('php-fpm', '/usr/sbin/php-fpm', 'httpd_t'),
                  ('AVC', 'avc:  denied  { name_connect } for  pid=77 comm="php-fpm" dest=9861 scontext=%s '
                          'tcontext=%s tclass=tcp_socket permissive=1' % (CTX % 'httpd_t', OBJ % 'unreserved_port_t'))]],
    'rule_fifo': [[proct('chronyc -n tracking'), sysc('chronyc', '/usr/bin/chronyc', 'chronyc_t'),
                   ('AVC', 'avc:  denied  { write } for  pid=4411 comm="chronyc" path="pipe:[123]" dev="pipefs" ino=123 '
                           'scontext=%s tcontext=%s tclass=fifo_file permissive=1' % (CTX % 'chronyc_t', CTX % 'unconfined_service_t'))]],
    'no_shadow': [[proct('/usr/local/lib/acme/python\0/usr/local/lib/acme/current/acme.py\0--daemon'),
                   path('/etc/shadow', 'shadow_t'), sysc('acme-backup', '/usr/local/lib/acme/python3.14', 'unconfined_service_t'),
                   ('AVC', 'avc:  denied  { read } for  pid=4410 comm="acme-backup" name="shadow" dev="dm-0" ino=9 '
                           'scontext=%s tcontext=%s tclass=file permissive=1' % (CTX % 'unconfined_service_t', OBJ % 'shadow_t'))]],
    'no_exec': [[cwd('/var/www/acme'), path('x.sh', 'shell_exec_t'), sysc('php-fpm', '/usr/sbin/php-fpm', 'httpd_t'),
                 ('AVC', 'avc:  denied  { execute } for  pid=77 comm="php-fpm" name="x.sh" dev="dm-0" ino=7 '
                         'scontext=%s tcontext=%s tclass=file permissive=1' % (CTX % 'httpd_t', OBJ % 'shell_exec_t'))]],
    'no_class': [[sysc('acme', '/usr/local/lib/acme/python3.14', 'unconfined_service_t'),
                  ('AVC', 'avc:  denied  { status } for  pid=4410 comm="acme" scontext=%s tcontext=%s tclass=system '
                          'permissive=1' % (CTX % 'unconfined_service_t', CTX % 'init_t'))]],
    'no_generic': [[path('/var/log/acme', 'var_log_t', 'PARENT', 0), path('acme.log.1', 'var_log_t', 'CREATE', 1),
                    sysc('logrotate', '/usr/sbin/logrotate', 'logrotate_t'),
                    ('AVC', 'avc:  denied  { write add_name } for  pid=88 comm="logrotate" name="acme.log.1" '
                            'scontext=%s tcontext=%s tclass=dir permissive=1' % (CTX % 'logrotate_t', OBJ % 'var_log_t'))]],
    'no_unlabelled': [[path('/var/lib/acme/acme.lock', 'default_t'), sysc('keepalived', '/usr/sbin/keepalived', 'keepalived_t'),
                       ('AVC', 'avc:  denied  { read } for  pid=55 comm="keepalived" name="acme.lock" '
                               'scontext=%s tcontext=%s tclass=file permissive=1' % (CTX % 'keepalived_t', OBJ % 'default_t'))]],
    'no_bool': [[path('/var/www/acme/share/a.html', 'nfs_t'), sysc('nginx', '/usr/sbin/nginx', 'httpd_t'),
                 ('AVC', 'avc:  denied  { read } for  pid=900 comm="nginx" name="a.html" scontext=%s tcontext=%s '
                         'tclass=file permissive=1' % (CTX % 'httpd_t', OBJ % 'nfs_t'))]],
    'no_port': [[sysc('sshd', '/usr/sbin/sshd', 'sshd_t'),
                 ('AVC', 'avc:  denied  { name_bind } for  pid=1 comm="sshd" src=8443 scontext=%s tcontext=%s '
                         'tclass=tcp_socket permissive=1' % (CTX % 'sshd_t', OBJ % 'http_port_t'))]],
    'no_err': [[sysc('acme-upgrade', '/usr/local/lib/acme/python3.14', 'unconfined_service_t'),
                ('SELINUX_ERR', 'op=security_compute_sid invalid_context="system_u:system_r:acme_t:s0" for scontext=%s '
                                'tcontext=%s tclass=process' % (CTX % 'unconfined_service_t', OBJ % 'bin_t'))]],
    'no_constraint': [[sysc('acme-net', '/usr/local/lib/acme/python3.14', 'unconfined_service_t'),
                       ('AVC', 'avc:  denied  { signal } for  pid=4410 comm="acme-net" scontext=%s tcontext=%s '
                               'tclass=process permissive=1' % (CTX % 'unconfined_service_t', CTX % 'unconfined_service_t'))]],
    'no_service': [[('USER_AVC', "pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  "
                                 "denied  { start } for auid=n/a uid=0 gid=0 path=\"/etc/systemd/system/acme-web.service\" "
                                 "cmdline=\"\" scontext=%s tcontext=%s tclass=service permissive=1 "
                                 "exe=\"/usr/lib/systemd/systemd\" sauid=0 hostname=? addr=? terminal=?'"
                                 % (CTX % 'unconfined_service_t', OBJ % 'systemd_unit_file_t'))]],
    'other_smbd': [[sysc('smbd', '/usr/sbin/smbd', 'smbd_t'),
                    ('AVC', 'avc:  denied  { write } for  pid=3 comm="smbd" name="home" scontext=%s tcontext=%s '
                            'tclass=dir permissive=1' % (CTX % 'smbd_t', OBJ % 'home_root_t'))]],
    'other_port': [[sysc('php-fpm', '/usr/sbin/php-fpm', 'httpd_t'),
                    ('AVC', 'avc:  denied  { name_connect } for  pid=77 comm="php-fpm" dest=9862 scontext=%s '
                            'tcontext=%s tclass=tcp_socket permissive=1' % (CTX % 'httpd_t', OBJ % 'unreserved_port_t'))]],
    'allowed_pg': [[path('/etc/pki/acme/ha-ca.pem', 'cert_t'), sysc('postgres', '/usr/bin/postgres', 'postgresql_t'),
                    ('AVC', 'avc:  denied  { read } for  pid=600 comm="postgres" name="ha-ca.pem" scontext=%s '
                            'tcontext=%s tclass=file permissive=1' % (CTX % 'postgresql_t', OBJ % 'cert_t'))]],
    'label_hex': [[path('/var/www/acme/my page.php', 'default_t'), sysc('php-fpm', '/usr/sbin/php-fpm', 'httpd_t'),
                   ('AVC', 'avc:  denied  { getattr } for  pid=77 comm="php-fpm" name=%s scontext=%s tcontext=%s '
                           'tclass=file permissive=1' % (hexs('my page.php'), CTX % 'httpd_t', OBJ % 'default_t'))]],
    'rule_keepalived': [[path('/run/acme/vip-state', 'httpd_var_run_t'), sysc('keepalived', '/usr/sbin/keepalived', 'keepalived_t'),
                         ('AVC', 'avc:  denied  { read } for  pid=55 comm="keepalived" name="vip-state" scontext=%s '
                                 'tcontext=%s tclass=file permissive=1' % (CTX % 'keepalived_t', OBJ % 'httpd_var_run_t'))]],
    'port_pg': [[sysc('postgres', '/usr/bin/postgres', 'postgresql_t'),
                 ('AVC', 'avc:  denied  { name_connect } for  pid=600 comm="postgres" dest=5433 scontext=%s '
                         'tcontext=%s tclass=tcp_socket permissive=1' % (CTX % 'postgresql_t', OBJ % 'unreserved_port_t'))]],
}
KIND = {'nnp_chronyc': 'rule', 'label_core': 'label', 'port_sshd': 'port', 'bool_api': 'boolean', 'rule_fifo': 'rule',
        'no_shadow': 'nobutton', 'no_exec': 'nobutton', 'no_class': 'nobutton', 'no_generic': 'nobutton',
        'no_unlabelled': 'nobutton', 'no_bool': 'nobutton', 'no_port': 'nobutton', 'no_err': 'nobutton',
        'no_constraint': 'nobutton', 'no_service': 'nobutton', 'other_smbd': 'other', 'other_port': 'other',
        'allowed_pg': 'allowed', 'label_hex': 'label', 'rule_keepalived': 'rule', 'port_pg': 'port'}
WHY = {'no_shadow': 'shadow_t is security-sensitive (file) - never allowed from here',
       'no_exec': 'file { execute } would let it run, change or reach far more than this - never allowed from here',
       'no_class': "the class system is the kernel's or the policy's own - never allowed from here",
       'no_generic': 'var_log_t is a type of the whole system - dir { add_name write } on it would let it change',
       'no_unlabelled': 'default_t is what the policy gives a file it has no label for',
       'no_bool': 'only the boolean httpd_use_nfs would allow it - it allows far more than this',
       'no_port': "port 8443/tcp is http_port_t - another service's; acme never takes a port from it",
       'no_err': 'SELinux could not work out a context for it (security_compute_sid)',
       'no_constraint': 'a constraint of the policy refuses it, not a missing rule',
       'no_service': "the class service is the kernel's or the policy's own"}
# What the stand-in policy's audit2why says beyond "Missing type enforcement": booleans, constraints.
A2W_BOOLS = {('httpd_t', 'unreserved_port_t', 'tcp_socket', 'name_connect'): 'httpd_can_network_connect',
             ('httpd_t', 'nfs_t', 'file', 'read'): 'httpd_use_nfs'}
A2W_CONSTRAINT = {('unconfined_service_t', 'unconfined_service_t', 'process', 'signal')}
# What matchpathcon says (the longest prefix): the policy's labels.
FCON = {'/var/www/acme': 'httpd_sys_content_t', '/run/acme': 'httpd_var_run_t', '/var/log/acme': 'var_log_t',
        '/etc/pki/acme': 'cert_t', '/usr/libexec/keepalived': 'keepalived_unconfined_script_exec_t'}
MINE = [{'port': 9861, 'proto': 'tcp', 'why': 'the API'}, {'port': 2222, 'proto': 'tcp', 'why': 'sshd (the console)'},
        {'port': 5433, 'proto': 'tcp', 'why': "the other node's PostgreSQL"},
        {'port': 8443, 'proto': 'tcp', 'why': 'the certificate sign-in'}]
WANT = {'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages ask the daemon on 127.0.0.1:9861'}],
        'ports': [{'port': 2222, 'proto': 'tcp', 'type': 'ssh_port_t', 'why': 'the SSH server listens on it'}],
        'mine': MINE}


def fixture(names, extra_ts=0):
    out = []
    for i, name in enumerate(names):
        for j, recs in enumerate(FIX[name]):
            out.append(event(i * 7 + j + 1, recs, BOOT + (i * 7 + j + 1) * 10 + extra_ts))
    return '\n'.join(out) + '\n'


class Machine(object):
    """A machine with SELinux, as root's helper sees it through its tools."""

    def __init__(self, d, mode='Permissive', avc='', allowed_names=(), modules=('acme_server', 'base')):
        self.d, self.mode, self.avc = d, mode, avc
        self.booleans = {'httpd_can_network_connect': False, 'httpd_use_nfs': False}
        self.ports = [('ssh_port_t', 'tcp', 22, 22), ('http_port_t', 'tcp', 80, 80), ('http_port_t', 'tcp', 443, 443),
                      ('http_port_t', 'tcp', 8443, 8443), ('postgresql_port_t', 'tcp', 5432, 5432)]
        self.modules = set(modules)
        self.local = []                        # the rules of acme_local as loaded
        self.allowed_names = set(allowed_names)
        self.ran = []
        self.fail_semodule = False
        self.labels_file = os.path.join(d, 'labels.json')
        self.labels = {p: want for p, want, _why in W.SE_LABELS}
        self.save()

    def save(self):
        with open(self.labels_file, 'w') as f:
            json.dump(self.labels, f)

    @staticmethod
    def want(p):
        best = ''
        for k in FCON:
            if (p == k or p.startswith(k + '/')) and len(k) > len(best):
                best = k
        return FCON.get(best, '')

    def allowed(self, line):
        m = re.search(r'scontext=\S+:(\w+):s0 tcontext=\S+:(\w+):s0 tclass=(\w+)', line)
        p = re.search(r'denied\s+\{([^}]*)\}', line)
        if not m or not p:
            return False
        st, tt, cls = m.groups()
        perms = set(p.group(1).split())
        for r in self.local:
            if (r[0], r[1], r[2]) == (st, tt, cls) and perms <= set(r[3]):
                return True
        for name in self.allowed_names:
            if any(rec[1] in line for ev in FIX[name] for rec in ev if rec[0] == 'AVC'):
                return True
        key = (st, tt, cls, ' '.join(sorted(perms)))
        return bool(A2W_BOOLS.get(key) and self.booleans.get(A2W_BOOLS[key]))

    def run(self, cmd, timeout=120, light=False, data=None):
        self.ran.append(list(cmd))
        r = lambda out='', rc=0, err='': SimpleNamespace(stdout=out, stderr=err, returncode=rc)  # noqa: E731
        c, a = cmd[0], cmd[1:]
        if self.mode == 'absent':
            return None
        if c == 'getenforce':
            return r(self.mode + '\n')
        if c == 'setenforce':
            self.mode = 'Enforcing' if a == ['1'] else 'Permissive'
            return r()
        if c == 'getsebool':
            if a == ['-a']:
                return r(''.join('%s --> %s\n' % (k, 'on' if v else 'off') for k, v in sorted(self.booleans.items())))
            return r('%s --> %s\n' % (a[0], 'on' if self.booleans.get(a[0]) else 'off'))
        if c == 'setsebool':
            self.booleans[a[1]] = a[2] in ('1', 'on')
            return r()
        if c == 'semanage' and a[:2] == ['port', '-l']:
            return r(''.join('%-28s %-7s %s\n' % (t, p, '%d' % lo if lo == hi else '%d-%d' % (lo, hi))
                             for t, p, lo, hi in self.ports))
        if c == 'semanage' and a[:2] == ['port', '-a']:
            t, proto, port = a[3], a[5], int(a[6])
            if any(p == proto and lo <= port <= hi for _t, p, lo, hi in self.ports):
                return r('', 1, 'ValueError: Port %s/%d already defined' % (proto, port))
            self.ports.append((t, proto, port, port))
            return r()
        if c == 'semodule' and a == ['-l']:
            return r(''.join(m + '\n' for m in sorted(self.modules)))
        if c == 'semodule' and a[:1] == ['-i']:
            if self.fail_semodule:
                return r('', 1, 'Failed to resolve AST')
            text = open(a[1]).read()
            if a[1].endswith('acme_local.cil'):
                depth = 0
                for line in text.splitlines():
                    code = line.split(';')[0]
                    if code.strip().startswith('(allow'):
                        assert depth == 1, 'a rule outside its optional block: %s' % line
                    depth += code.count('(') - code.count(')')
                assert depth == 0
                self.local = [(m.group(1), m.group(2), m.group(3), m.group(4).split())
                              for m in re.finditer(r'\(allow (\w+) (\w+) \((\w+) \(([^)]*)\)\)\)', text)]
                self.modules.add('acme_local')
            else:
                self.modules.add(os.path.basename(a[1]).split('.')[0])
            return r()
        if c == 'semodule' and a[:1] == ['-r']:
            self.modules.discard(a[1])
            if a[1] == 'acme_local':
                self.local = []
            return r()
        if c == 'ausearch':
            return r(self.avc)
        if c == 'audit2why':
            out = []
            for line in (data or '').splitlines():
                out.append(line)
                m = re.search(r'scontext=\S+:(\w+):s0 tcontext=\S+:(\w+):s0 tclass=(\w+)', line)
                p = re.search(r'denied\s+\{([^}]*)\}', line)
                key = (m.groups() + (' '.join(sorted(p.group(1).split())),)) if m and p else None
                if self.allowed(line):
                    out.append('\n\tWas caused by:\n\t\tUnknown - would be allowed by active policy\n'
                               '\t\tPossible mismatch between this policy and the one under which the audit message was generated.\n')
                elif key and key in A2W_BOOLS:
                    b = A2W_BOOLS[key]
                    out.append('\n\tWas caused by:\n\tThe boolean %s was set incorrectly. \n\tDescription:\n\tAllow it\n\n'
                               '\tAllow access by executing:\n\t# setsebool -P %s 1\n' % (b, b))
                elif key and key[:3] + (key[3],) in A2W_CONSTRAINT:
                    out.append('\n\tWas caused by:\n\t\tPolicy constraint violation.\n')
                else:
                    out.append('\n\tWas caused by:\n\t\tMissing type enforcement (TE) allow rule.\n\n'
                               '\t\tYou can use audit2allow to generate a loadable module to allow this access.\n')
            return r('\n'.join(out) + '\n')
        if c == 'matchpathcon':
            w = self.want(a[-1])
            return r('system_u:object_r:%s:s0\n' % w) if w else r('', 1, 'matchpathcon: no match')
        if c == 'restorecon':
            target = a[-1]
            for p in list(self.labels) + [target]:
                if p == target or p.startswith(target.rstrip('/') + '/'):
                    self.labels[p] = self.want(p)
            self.save()
            return r('Relabeled %s\n' % target)
        if c == 'systemctl':
            return r('active\n')
        if c == 'ps':
            return r('LABEL USER PID PPID COMMAND\n%s acme 11 1 /usr/local/lib/acme/python acme.py --daemon\n'
                     '%s nginx 10 1 nginx: worker process\n' % (CTX % 'unconfined_service_t', CTX % 'httpd_t'))
        return r()


REAL_LEXISTS, REAL_ISDIR = os.path.lexists, os.path.isdir


class Base(unittest.TestCase):
    W = W

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-sefind-m-')
        w = self.W
        self.snap = w.NET_SNAP_DIR
        shutil.rmtree(self.snap, ignore_errors=True)
        os.makedirs(self.snap, mode=0o700)
        self.conf = os.path.join(self.d, 'config')
        with open(self.conf, 'w') as f:
            f.write('SELINUX=permissive\nSELINUXTYPE=targeted\n')
        w.SE_CONFIG = self.conf
        w.SE_RELABEL = os.path.join(self.d, '.autorelabel')
        w.SE_CMDLINE = os.path.join(self.d, 'cmdline')
        with open(w.SE_CMDLINE, 'w') as f:
            f.write('ro quiet\n')
        w.SE_CIL = os.path.join(self.d, 'acme_server.cil')
        w.NGINX_DIR = os.path.join(self.d, 'nginx')       # nothing of the machine running this test read
        w.SSH_DIR = os.path.join(self.d, 'ssh')
        w.WEB_DIR = os.path.join(TMP, 'web')
        os.environ['ACME_SELINUX_AUDITD'] = 'active'
        self.m = Machine(self.d, avc=fixture(list(FIX)), allowed_names=['allowed_pg'])
        os.environ['ACME_SELINUX_LABELS'] = self.m.labels_file
        w._se_run = self.m.run
        self.had_which = w.shutil.which
        w.shutil.which = lambda c: None if c in ('restorecon', 'grubby') else '/usr/bin/' + c
        self.exists = {'/var/www/acme/assets', '/var/www/acme', '/var/www/acme/assets/core.js'}
        self.p1 = mock.patch('os.path.lexists', side_effect=lambda p: p in self.exists or REAL_LEXISTS(p))
        self.p2 = mock.patch('os.path.isdir', side_effect=lambda p: p in ('/var/www/acme/assets', '/var/www/acme') or REAL_ISDIR(p))
        self.p1.start()
        self.p2.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.W.shutil.which = self.had_which
        os.environ.pop('ACME_SELINUX_AUDITD', None)
        os.environ.pop('ACME_SELINUX_LABELS', None)

    def look(self, want=None):
        return self.W.se_check(dict(WANT if want is None else want))

    def by_name(self, c):
        """{fixture name: finding} - by what the fixture refused (program, source, target, class)."""
        out = {}
        for name in FIX:
            avcs = [r[1] for ev in FIX[name] for r in ev if r[0] in ('AVC', 'USER_AVC', 'SELINUX_ERR')]
            m = re.search(r'scontext=\S+:(\w+):s0 tcontext=\S+:(\w+):s0 tclass=(\w+)', avcs[0])
            port = re.search(r'(?:dest|src)=(\d+)', avcs[0])
            perms = re.search(r'denied\s+\{([^}]*)\}', avcs[0])
            for f in c.get('findings') or []:
                if (f['source'], f['target'], f['class']) == m.groups() and \
                        (not port or f.get('port') == int(port.group(1))) and \
                        (not perms or f['perms'] == ' '.join(sorted(perms.group(1).split()))):
                    out.setdefault(name, f)
        return out


class Analysis(Base):
    def test_hex_decoded_only_for_strings(self):
        ev = self.W.se_events(fixture(['label_hex', 'nnp_chronyc', 'no_exec', 'no_generic', 'port_sshd']))
        refs = [r for e in ev for r in self.W.se_refusals(e)]
        hexed = [r for r in refs if r['target'] == 'default_t'][0]
        self.assertEqual(hexed['path'], '/var/www/acme/my page.php')       # PATH name, hex
        nnp = [r for r in refs if r['target'] == 'chronyc_t'][0]
        self.assertEqual(nnp['proctitle'], '/usr/local/lib/acme/python /usr/local/lib/acme/current/acme.py --daemon')
        self.assertEqual(nnp['program'], 'acme-clock')
        self.assertEqual(nnp['exe'], '/usr/local/lib/acme/python3.14')
        rel = [r for r in refs if r['target'] == 'shell_exec_t'][0]
        self.assertEqual(rel['path'], '/var/www/acme/x.sh')               # name made whole with cwd
        made = [r for r in refs if r['target'] == 'var_log_t'][0]
        self.assertEqual(made['path'], '/var/log/acme/acme.log.1')         # the folder it was made in
        port = [r for r in refs if r['class'] == 'tcp_socket'][0]
        self.assertEqual((port['port'], port['proto']), (2222, 'tcp'))
        # A port is never "decoded", even when it looks like hex: digits stay digits.
        self.assertEqual(self.W._se_val('src', '2222'), '2222')
        self.assertEqual(self.W._se_val('comm', '414243'), 'ABC')
        self.assertEqual(self.W._se_val('dest', '414243'), '414243')
        self.assertEqual(self.W._se_val('name', '"plain"'), 'plain')

    def test_user_avc_and_selinux_err(self):
        ev = self.W.se_events(fixture(['no_service', 'no_err']))
        refs = [r for e in ev for r in self.W.se_refusals(e)]
        ua = [r for r in refs if r['class'] == 'service'][0]
        self.assertEqual(ua['path'], '/etc/systemd/system/acme-web.service')
        self.assertEqual(ua['perms'], ['start'])
        err = [r for r in refs if r['err']][0]
        self.assertEqual((err['source'], err['perms'], err['program']), ('unconfined_service_t', ['security_compute_sid'], 'acme-upgrade'))

    def test_grouped_and_ids_stable(self):
        c1 = self.look()
        c2 = self.look()
        ids1 = sorted(f['id'] for f in c1['findings'])
        self.assertEqual(ids1, sorted(f['id'] for f in c2['findings']))
        self.assertEqual(len(ids1), len(set(ids1)))
        f = self.by_name(c1)
        self.assertEqual(f['nnp_chronyc']['count'], 2)                     # two events, one group
        self.assertEqual(f['label_core']['count'], 2)
        key = ('unconfined_service_t', 'chronyc_t', 'process2', 'nnp_transition', 'acme-clock', '')
        self.assertEqual(f['nnp_chronyc']['id'], hashlib.sha256('\0'.join(key).encode()).hexdigest()[:12])
        for x in c1['findings']:
            self.assertRegex(x['id'], r'^[0-9a-f]{12}$')
            self.assertNotIn('proctitle', x)                               # no command line on the card
            self.assertNotIn('line', x)
        # The same refusal on another machine has the same id; another permission another group.
        more = fixture(list(FIX)) + event(900, [sysc('nginx', '/usr/sbin/nginx', 'httpd_t'), path('/var/www/acme/assets/core.js', 'default_t'),
                                                 ('AVC', 'avc:  denied  { open } for  pid=900 comm="nginx" name="core.js" scontext=%s '
                                                         'tcontext=%s tclass=file permissive=1' % (CTX % 'httpd_t', OBJ % 'default_t'))]) + '\n'
        self.m.avc = more
        c3 = self.look()
        self.assertEqual(len(c3['findings']), len(c1['findings']) + 1)

    def test_every_kind(self):
        c = self.look()
        f = self.by_name(c)
        for name, kind in KIND.items():
            if kind == 'allowed':
                self.assertNotIn(name, f)                                  # not shown, not counted
                continue
            self.assertEqual(f[name]['kind'], kind, (name, f[name]))
        for name, why in WHY.items():
            self.assertIn(why, f[name]['why'], name)
            self.assertFalse(f[name]['fixable'])
        self.assertEqual(f['bool_api']['fix'], 'setsebool -P httpd_can_network_connect 1')
        self.assertEqual(f['label_core']['fix'], 'restorecon -R -v /var/www/acme/assets')
        self.assertIn('/var/www/acme/assets/core.js is labelled default_t - the policy says httpd_sys_content_t', f['label_core']['why'])
        self.assertEqual(f['label_hex']['fix'], 'restorecon -R -v /var/www/acme')
        self.assertEqual(f['port_sshd']['fix'], 'semanage port -a -t ssh_port_t -p tcp 2222')
        self.assertEqual(f['port_pg']['fix'], 'semanage port -a -t postgresql_port_t -p tcp 5433')     # the replication
        self.assertEqual(f['nnp_chronyc']['fix'], '(allow unconfined_service_t chronyc_t (process2 (nnp_transition)))')
        self.assertEqual(f['rule_fifo']['fix'], '(allow chronyc_t unconfined_service_t (fifo_file (write)))')
        self.assertEqual(f['rule_keepalived']['fix'], '(allow keepalived_t httpd_var_run_t (file (read)))')   # the VIP's check
        self.assertIn("not acme's: smbd (smbd_t) is another program of this machine", f['other_smbd']['why'])
        self.assertTrue(all(x['fixable'] for x in c['findings'] if x['kind'] in ('boolean', 'label', 'port', 'rule')))
        self.assertEqual(c['denials']['settled'], 1)                       # allowed now: postgresql_t -> cert_t
        self.assertEqual(c['found']['counts']['other'], 2)
        # Sorted: what can be put right first, then not for a button, then not acme's.
        kinds = [x['kind'] for x in c['findings']]
        self.assertEqual(kinds, sorted(kinds, key=['fixed', 'boolean', 'label', 'port', 'rule', 'nobutton', 'other'].index))
        # Not acme's never blocks: counted are acme's open ones.
        self.assertEqual(c['denials']['total'], sum(x['count'] for x in c['findings'] if x['kind'] not in ('other', 'fixed')))
        self.assertIn('SELinux refused %d thing(s) since the machine started' % c['denials']['total'], c['problems'])

    def test_whose_by_paths_ports_programs(self):
        g = {'source': 'httpd_t', 'target': 'x_t', 'class': 'file', 'perms': ['read'], 'program': 'nginx', 'exe': '',
             'proctitle': '', 'path': '', 'name': '', 'port': 0, 'proto': '', 'id': 'a' * 12, 'last': 1, 'err': False}
        for p in ('/usr/local/lib/acme/current/acme.py', '/var/lib/acme/acme.db', '/etc/acme/config.json',
                  '/var/www/acme/index.php', '/run/acme/api-token', '/run/acme-osup.lock', '/var/log/acme/acme.log',
                  '/etc/nginx/conf.d/acme_vip.conf', '/etc/nginx/conf.d/acme_agents.conf', '/etc/nginx/certs/acme.pem',
                  '/etc/php-fpm.d/acme.conf', '/etc/ssh/sshd_config.d/00-acme.conf', '/etc/keepalived/keepalived.conf',
                  '/etc/systemd/system/keepalived.service.d/acme.conf', '/usr/libexec/keepalived/acme-vip-check',
                  '/etc/logrotate.d/acme', '/etc/pki/acme/ha-ca.pem', '/var/lib/pgsql/data/acme-ha.crt',
                  '/var/lib/acme-net/selinux-applied', '/etc/rsyslog.d/10-acme-tls.conf'):
            self.assertTrue(self.W.se_acme_path(p), p)
            self.assertTrue(self.W.se_sort(dict(g, path=p), {}, {}, {}, lambda x: '')['acme'], p)
        for p in ('/etc/shadow', '/var/www/html/x', '/etc/nginx/conf.d/other.conf', '/run/acmex', '/home/acme'):
            self.assertFalse(self.W.se_acme_path(p), p)
        ports = self.W.se_acme_ports({'mine': [[2222, 'tcp', 'sshd']]})
        for k in ((9861, 'tcp'), (80, 'tcp'), (443, 'tcp'), (2222, 'tcp')):
            self.assertIn(k, ports)
        # Root reads acme's own files too: the listen ports of its nginx files, sshd's Port.
        os.makedirs(self.W.NGINX_DIR, exist_ok=True)
        with open(os.path.join(self.W.NGINX_DIR, 'acme_agents.conf'), 'w') as f:
            f.write('server {\n    listen 0.0.0.0:8444 ssl;\n    listen [::]:8444 ssl;\n}\n')
        with open(os.path.join(self.W.NGINX_DIR, 'other.conf'), 'w') as f:
            f.write('server { listen 9999; }\n')
        os.makedirs(os.path.join(self.W.SSH_DIR, 'sshd_config.d'), exist_ok=True)
        with open(os.path.join(self.W.SSH_DIR, self.W.SSHD_DROPIN), 'w') as f:
            f.write('Port 2299\n')
        ports = self.W.se_acme_ports({})
        self.assertIn((8444, 'tcp'), ports)
        self.assertIn((2299, 'tcp'), ports)
        self.assertNotIn((9999, 'tcp'), ports)
        # The confined services: acme's only by its paths and ports; acme's programs by themselves.
        self.assertFalse(self.W.se_sort(dict(g, path='/etc/passwd'), {}, ports, {}, lambda x: '')['acme'])
        self.assertTrue(self.W.se_sort(dict(g, source='unconfined_service_t', program='acme-alerts'), {}, ports, {},
                                       lambda x: '')['acme'])
        self.assertTrue(self.W.se_sort(dict(g, source='ssh_t', target='unconfined_service_t', program='ssh'), {}, ports, {},
                                       lambda x: '')['acme'])
        self.assertFalse(self.W.se_sort(dict(g, source='smbd_t', path='/var/lib/acme/x'), {}, ports, {}, lambda x: '')['acme'])


class PutRight(Base):
    def fixable(self, c):
        return [f for f in c['findings'] if f['fixable']]

    def test_fix_by_ids(self, mode='Permissive'):
        self.m.mode = mode
        c = self.look()
        f = self.by_name(c)
        ids = [f[n]['id'] for n in ('bool_api', 'label_core', 'port_sshd', 'nnp_chronyc', 'rule_fifo', 'port_pg')]
        self.m.ran = []
        got = self.W.se_do({'do': 'fix', 'ids': ids, 'by': 'admin'})
        ran = [x for x in self.m.ran if x[0] in ('setsebool', 'restorecon', 'semanage', 'semodule') and x[1:2] != ['-l']
               and x[1:3] != ['port', '-l']]
        self.assertIn(['setsebool', '-P', 'httpd_can_network_connect', '1'], ran)
        self.assertIn(['restorecon', '-R', '-v', '/var/www/acme/assets'], ran)
        self.assertIn(['semanage', 'port', '-a', '-t', 'ssh_port_t', '-p', 'tcp', '2222'], ran)
        self.assertIn(['semanage', 'port', '-a', '-t', 'postgresql_port_t', '-p', 'tcp', '5433'], ran)
        cil = os.path.join(self.W.NET_SNAP_DIR, 'acme_local.cil')
        self.assertIn(['semodule', '-i', cil], ran)
        self.assertEqual(len(ran), 5, ran)                                 # exactly that, nothing else
        text = open(cil).read()
        self.assertIn('(optional acme_local_%s\n    (allow unconfined_service_t chronyc_t (process2 (nnp_transition))))'
                      % f['nnp_chronyc']['id'], text)
        self.assertIn('(allow chronyc_t unconfined_service_t (fifo_file (write)))', text)
        self.assertEqual(open(cil + '.in-policy').read(), text)
        self.assertEqual(os.stat(cil).st_mode & 0o777, 0o600)
        self.assertIn('the boolean httpd_can_network_connect is on', got['said'])
        self.assertIn('port 2222/tcp labelled ssh_port_t', got['said'])
        self.assertTrue(any(s.startswith("acme's local module (acme_local) put into the policy - 2 rule(s)") for s in got['said']))
        # Looked again at once: what was put right is no longer open.
        after = self.by_name(got)
        for n in ('bool_api', 'nnp_chronyc', 'rule_fifo'):
            self.assertNotIn(n, after)                                     # the policy allows it now
        for n in ('label_core', 'port_sshd', 'port_pg'):
            self.assertEqual(after[n]['kind'], 'fixed', n)
        self.assertEqual([r['id'] for r in got['local']['rules']], [f['nnp_chronyc']['id'], f['rule_fifo']['id']])
        self.assertTrue(got['local']['in_policy'])
        self.assertEqual(self.m.mode, mode)                                # nothing switched off for it
        # Refused again after it was put right: it comes back.
        self.m.avc += event(990, FIX['label_core'][0], int(time.time()) + 5) + '\n'
        again = self.by_name(self.look())
        self.assertEqual(again['label_core']['kind'], 'label')
        return got

    def test_fix_under_enforcing(self):
        self.test_fix_by_ids('Enforcing')

    def test_only_ids(self):
        c = self.look()
        f = self.by_name(c)
        for bad in ({'do': 'fix', 'ids': [f['bool_api']['id']], 'rule': '(allow httpd_t shadow_t (file (read)))'},  # noqa
                    {'do': 'fix', 'ids': [f['bool_api']['id']], 'path': '/'},
                    {'do': 'fix', 'ids': [f['bool_api']['id']], 'booleans': [{'name': 'httpd_can_network_connect'}]},
                    {'do': 'fix', 'ids': ['restorecon -R /']}, {'do': 'fix', 'ids': 'abc'}, {'do': 'fix', 'ids': []},
                    {'do': 'fix', 'ids': ['ABCDEF123456']}, {'do': 'rule_drop', 'ids': ['x' * 12]},
                    {'do': 'fix', 'ids': [f['bool_api']['id']], 'cmd': 'id'}):
            self.m.ran = []
            with self.assertRaises(self.W.Refused, msg=repr(bad)):
                self.W.se_do(bad)
            self.assertFalse([x for x in self.m.ran if x[0] in ('setsebool', 'restorecon', 'semodule') and x[1:] != ['-l']])
        # Through the helper's door (selinux.ask): refused, said, nothing done.
        with open(os.path.join(TMP, 'web', 'selinux.ask'), 'w') as fh:
            fh.write(json.dumps({'id': 'q1', 'do': 'fix', 'ids': [f['bool_api']['id']],
                                 'fix': 'setsebool -P httpd_execmem 1'}))
        self.W.FD[0] = None
        self.W.selinux_part()
        with open(os.path.join(TMP, 'web', 'selinux.json')) as fh:
            ans = json.load(fh)
        self.assertFalse(ans['ok'])
        self.assertIn('names only the ids', ans['said'])
        # Not for a button, not acme's, gone: said, never done.
        self.m.ran = []
        got = self.W.se_do({'do': 'fix', 'ids': [f['no_shadow']['id'], f['other_smbd']['id'], 'abcdefabcdef',
                                                 f['bool_api']['id']]})
        words = ' | '.join(got['said'])
        self.assertIn('%s: not for a button' % f['no_shadow']['id'], words)
        self.assertIn("%s: not acme's" % f['other_smbd']['id'], words)
        self.assertIn('abcdefabcdef: not found any more', words)
        self.assertEqual([x for x in self.m.ran if x[0] == 'setsebool'], [['setsebool', '-P', 'httpd_can_network_connect', '1']])
        got = self.W.se_do({'do': 'fix', 'ids': [f['no_shadow']['id']]})   # nothing to do: said, not done
        self.assertEqual(len(got['said']), 1)
        # SELinux off: nothing to put right.
        self.m.mode = 'Disabled'
        with self.assertRaises(self.W.Refused):
            self.W.se_do({'do': 'fix', 'ids': [f['label_core']['id']]})

    def test_semodule_fails_list_stays_as_policy(self):
        c = self.look()
        f = self.by_name(c)
        self.m.fail_semodule = True
        with self.assertRaises(self.W.Refused):
            self.W.se_do({'do': 'fix', 'ids': [f['nnp_chronyc']['id']]})
        self.assertEqual(self.W.se_local_read(), [])

    def test_take_rules_away(self):
        got = self.test_fix_by_ids()
        rules = got['local']['rules']
        cil = os.path.join(self.W.NET_SNAP_DIR, 'acme_local.cil')
        out = self.W.se_do({'do': 'rule_drop', 'ids': [rules[0]['id']], 'by': 'admin'})
        self.assertTrue(any(s.startswith('rule %s taken away' % rules[0]['id']) for s in out['said']))
        self.assertNotIn('chronyc_t (process2', open(cil).read())
        self.assertEqual([r['id'] for r in out['local']['rules']], [rules[1]['id']])
        f = self.by_name(out)
        self.assertEqual(f['nnp_chronyc']['kind'], 'rule')               # refused, and nothing allows it any more
        out = self.W.se_do({'do': 'rule_drop', 'ids': [rules[1]['id']]})
        self.assertNotIn('acme_local', self.m.modules)
        self.assertIn(['semodule', '-r', 'acme_local'], self.m.ran)
        self.assertFalse(os.path.exists(cil))
        self.assertEqual(out['local']['rules'], [])
        with self.assertRaises(self.W.Refused):
            self.W.se_do({'do': 'rule_drop', 'ids': [rules[1]['id']]})

    def test_root_files_only_roots(self):
        # A list in root's folder the acme account could have written is not read (not root's): here,
        # as root, a file of another owner.
        if os.geteuid() != 0:
            self.skipTest('needs root to give a file another owner')
        p = os.path.join(self.W.NET_SNAP_DIR, 'selinux-local.json')
        with open(p, 'w') as fh:
            json.dump([{'id': 'a' * 12, 'source': 'httpd_t', 'target': 'shadow_t', 'class': 'file', 'perms': ['read']}], fh)
        os.chown(p, 990, 990)
        self.assertEqual(self.W.se_local_read(), [])


class Steps(Base):
    def test_lock_until_nothing_is_left(self):
        c = self.look()
        self.assertFalse(c['ready'])
        with self.assertRaises(self.W.Refused) as e:
            self.W.se_do(dict(WANT, do='enforce'))
        self.assertIn('not yet', str(e.exception))
        # Everything fixable put right: not for a button still locks it.
        self.m.booleans['httpd_can_network_connect'] = False
        ids = [x['id'] for x in c['findings'] if x['fixable']]
        self.W.se_do({'do': 'fix', 'ids': ids})
        c = self.look()
        self.assertFalse([x for x in c['findings'] if x['fixable']])
        self.assertTrue([x for x in c['findings'] if x['kind'] == 'nobutton'])
        self.assertFalse(c['ready'])
        # Only what is not acme's left: ready, and enforcing goes.
        self.m.avc = fixture(['other_smbd', 'other_port'])
        c = self.look()
        self.assertTrue(c['ready'], c['problems'])
        out = self.W.se_do(dict(WANT, do='enforce'))
        self.assertEqual(self.m.mode, 'Enforcing')
        self.assertIn('SELINUX=enforcing', open(self.conf).read())
        self.assertIn('SELinux is enforcing, and stays so after a restart', out['said'])
        out = self.W.se_do(dict(WANT, do='permissive'))
        self.assertEqual(self.m.mode, 'Permissive')

    def test_prepare_from_disabled(self):
        self.m.mode = 'Disabled'
        with open(self.conf, 'w') as f:
            f.write('SELINUX=disabled\n')
        with open(self.W.SE_CIL, 'w') as f:
            f.write('(filecon "/run/acme" dir (system_u object_r httpd_var_run_t ((s0) (s0))))\n')
        out = self.W.se_do(dict(WANT, do='prepare'))
        self.assertIn('SELINUX=permissive', open(self.conf).read())
        self.assertTrue(os.path.exists(self.W.SE_RELABEL))
        self.assertIn("acme's module installed", out['said'])
        self.assertEqual(out['findings'] if 'findings' in out else [], [])  # disabled: nothing looked at


class Report(Base):
    def test_every_file_and_nothing_secret(self):
        def out(cmd, timeout=120, data=None, light=True):
            got = self.m.run(cmd, timeout, light, data)
            return '(%s is not on this machine)\n' % cmd[0] if got is None else (got.stdout or '')
        self.addCleanup(setattr, self.W, '_se_out', self.W._se_out)
        self.W._se_out = out
        token = 'Api-T0ken-4711'
        with open(os.path.join(TMP, 'api-token'), 'w') as f:
            f.write(token)
        data = self.W.se_report_bytes(dict(WANT, facts=E.selinux_facts(STORE)), 'acme-a')
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            texts = {n: tf.extractfile(n).read().decode('utf-8', 'replace') for n in names}
        for part in ('check.json', 'acme.json', 'avc-raw.txt', 'avc.txt', 'audit2why.txt', 'audit2allow.te',
                     'labels.txt', 'processes.txt', 'ports.txt', 'booleans.txt', 'modules.txt', 'system.txt',
                     'README.txt', 'os/processes.txt', 'os/booleans.txt', 'os/ports.txt', 'os/modules.txt',
                     'os/local-changes.txt', 'os/semanage-export.txt', 'os/listening.txt'):
            self.assertIn('acme-a/' + part, names)
        check = json.loads(texts['acme-a/check.json'])
        self.assertTrue(check['findings'])
        self.assertNotIn('proctitle', texts['acme-a/check.json'])
        self.assertIn('nnp_transition', texts['acme-a/avc-raw.txt'])
        self.assertIn('httpd_can_network_connect', texts['acme-a/os/booleans.txt'])
        self.assertIn('acme_local', texts['acme-a/modules.txt'])
        for secret in ('Db-S3cret-4711', 'Snmp-S3cret-4711', token):
            for n, t in texts.items():
                self.assertNotIn(secret, t, n)
        # Nothing was changed to make it.
        self.assertFalse([x for x in self.m.ran if x[0] in ('setsebool', 'restorecon', 'setenforce') or
                          x[:2] in (['semodule', '-i'], ['semodule', '-r']) or x[:3] == ['semanage', 'port', '-a']])


class TwoNodes(unittest.TestCase):
    """Each node finds, and puts right, only its own: SELinux is each machine's."""

    @classmethod
    def setUpClass(cls):
        cls.A, cls.B = W, helper(os.path.join(TMP, 'root-b'))
        os.environ['ACME_NET_SNAP_DIR'] = os.path.join(TMP, 'root-a')

    def setUp(self):
        self.me = E.node_name()
        STORE.set_meta('node:acme-b', json.dumps({'at': time.time() + 3600}))
        for k in ('host:selinux:want:', 'host:selinux:now:'):
            for n in (self.me, 'acme-b'):
                STORE.db.run('DELETE FROM meta WHERE k = ?', (k + n,))
        self.ma = Machine(tempfile.mkdtemp(), avc=fixture(['bool_api', 'label_core', 'rule_keepalived']))
        self.mb = Machine(tempfile.mkdtemp(), mode='Enforcing', avc=fixture(['nnp_chronyc', 'port_pg']))
        for w, m in ((self.A, self.ma), (self.B, self.mb)):
            w._se_run = m.run
            w.SE_CONFIG = os.path.join(m.d, 'config')
            with open(w.SE_CONFIG, 'w') as f:
                f.write('SELINUX=%s\n' % m.mode.lower())
            w.SE_CIL = os.path.join(m.d, 'acme_server.cil')
            w.NGINX_DIR = w.SSH_DIR = os.path.join(m.d, 'none')
            shutil.rmtree(w.NET_SNAP_DIR, ignore_errors=True)
            os.makedirs(w.NET_SNAP_DIR, mode=0o700)
        os.environ['ACME_SELINUX_AUDITD'] = 'active'
        # A replicated cluster: the other node's PostgreSQL on 5433 is acme's port.
        self.conf = mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated', 'ha_peer': '192.0.2.2', 'ha_peer_port': 5433,
                                               'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': 5432})
        self.conf.start()

    def tearDown(self):
        self.conf.stop()
        STORE.db.run("DELETE FROM meta WHERE k = 'node:acme-b'")
        os.environ.pop('ACME_SELINUX_AUDITD', None)

    def tick(self, node, w):
        """The daemon of `node` once: its want row, its root helper (in-process)."""
        def ask(name, ans, data, wait=60):
            self.assertEqual(name, 'selinux.ask')
            self.asked.append((node, dict(data)))
            if data.get('do') in ('fix', 'rule_drop'):
                self.assertEqual(set(data), {'do', 'ids', 'by'})            # the ids alone
            out = w.se_do(dict(data))
            return out
        had = dict(E.SE_WORK)
        E.SE_WORK.update(busy=False, seen=time.time(), tried='')
        try:
            with mock.patch.dict(E.selinux_tick.__globals__, {'node_name': lambda: node, 'root_ask': ask}), \
                    mock.patch.object(E.threading, 'Thread') as T:
                T.side_effect = lambda target=None, **kw: SimpleNamespace(start=target)
                E.selinux_tick(SimpleNamespace(store=STORE))
        finally:
            E.SE_WORK.clear()
            E.SE_WORK.update(had)

    def look_both(self):
        for n, w in ((self.me, self.A), ('acme-b', self.B)):
            STORE.set_meta('host:selinux:want:' + n, json.dumps({'id': 'look' + n[-1], 'do': 'check', 'by': 't', 'at': time.time()}))
            self.tick(n, w)

    def test_findings_and_fixes_per_node(self):
        self.asked = []
        self.look_both()
        v = E.selinux_view(STORE)
        self.assertTrue(v['cluster'])
        by = {n['name']: n for n in v['nodes']}
        fa = {f['source'] + '>' + f['target']: f for f in by[self.me]['state']['findings']}
        fb = {f['source'] + '>' + f['target']: f for f in by['acme-b']['state']['findings']}
        self.assertEqual(set(fa), {'httpd_t>unreserved_port_t', 'httpd_t>default_t', 'keepalived_t>httpd_var_run_t'})
        self.assertEqual(set(fb), {'unconfined_service_t>chronyc_t', 'postgresql_t>unreserved_port_t'})
        self.assertEqual(by['acme-b']['state']['mode'], 'Enforcing')
        self.assertEqual(by[self.me]['state']['mode'], 'Permissive')
        # An id of B's asked of A: refused - A never found it.
        with self.assertRaises(ValueError) as e:
            E.selinux_ask(STORE, self.me, 'fix', 'admin', ids=[fb['unconfined_service_t>chronyc_t']['id']])
        self.assertIn('each node puts right only what it found itself', str(e.exception))
        # Asked of B: written for B, with the ids alone.
        E.selinux_ask(STORE, 'acme-b', 'fix', 'admin', ids=[fb['unconfined_service_t>chronyc_t']['id'],
                                                            fb['postgresql_t>unreserved_port_t']['id']])
        row = json.loads(STORE.get_meta('host:selinux:want:acme-b'))
        self.assertEqual(set(row), {'id', 'do', 'by', 'at', 'ids'})
        self.assertEqual(json.loads(STORE.get_meta('host:selinux:want:' + self.me))['do'], 'check')
        # A's daemon looks at its own row only: nothing of B's is done on A.
        self.asked = []
        self.ma.ran = []
        STORE.set_meta('host:selinux:want:' + self.me, json.dumps({'id': 'again', 'do': 'check', 'by': 't', 'at': time.time()}))
        self.tick(self.me, self.A)
        self.assertEqual([a[1]['do'] for a in self.asked], ['check'])
        self.assertFalse([x for x in self.ma.ran if x[0] in ('setsebool', 'semanage', 'restorecon') and '-l' not in x
                          or x[:2] == ['semodule', '-i']])
        # B's daemon does it, by its root, under enforcing - and looks again.
        self.asked = []
        self.tick('acme-b', self.B)
        self.assertEqual(self.asked[0][1]['do'], 'fix')
        self.assertIn(['semanage', 'port', '-a', '-t', 'postgresql_port_t', '-p', 'tcp', '5433'], self.mb.ran)
        self.assertIn('acme_local', self.mb.modules)
        self.assertNotIn('acme_local', self.ma.modules)
        self.assertEqual(self.mb.mode, 'Enforcing')
        self.assertTrue(os.path.exists(os.path.join(self.B.NET_SNAP_DIR, 'acme_local.cil')))
        self.assertFalse(os.path.exists(os.path.join(self.A.NET_SNAP_DIR, 'acme_local.cil')))
        v = E.selinux_view(STORE)
        by = {n['name']: n for n in v['nodes']}
        self.assertEqual(len(by['acme-b']['state']['local']['rules']), 1)
        self.assertEqual(by[self.me]['state'].get('local', {}).get('rules'), [])
        self.assertFalse(by['acme-b']['pending'])
        ev = [r['words'] for r in STORE.db.rows("SELECT * FROM events ORDER BY id DESC LIMIT 12")]
        self.assertTrue(any(w.startswith('SELinux on acme-b: port 5433/tcp labelled postgresql_port_t') for w in ev), ev)
        self.assertTrue(any('admin asked SELinux on acme-b: put right 2 thing(s)' in w for w in ev), ev)
        # A rule of B's local module taken away only on B.
        rid = by['acme-b']['state']['local']['rules'][0]['id']
        with self.assertRaises(ValueError):
            E.selinux_ask(STORE, self.me, 'rule_drop', 'admin', ids=[rid])
        E.selinux_ask(STORE, 'acme-b', 'rule_drop', 'admin', ids=[rid])
        self.tick('acme-b', self.B)
        self.assertNotIn('acme_local', self.mb.modules)

    def test_one_node_at_a_time(self):
        self.asked = []
        self.look_both()
        E.selinux_ask(STORE, self.me, 'prepare', 'admin')
        # Advice, not a refusal: asking both nodes at once worked before 1.0.120 and still does.
        E.selinux_ask(STORE, 'acme-b', 'permissive', 'admin')
        with self.assertRaises(ValueError):
            E.selinux_ask(STORE, self.me, 'fix', 'admin', ids=['a' * 12])
        self.tick(self.me, self.A)                                         # done: the other may go
        E.selinux_ask(STORE, 'acme-b', 'permissive', 'admin')
        self.assertEqual(json.loads(STORE.get_meta('host:selinux:want:acme-b'))['do'], 'permissive')
        # Nothing of it is a setting: no CONFIG key goes to the other node.
        self.assertFalse([k for k in E.CONFIG if 'selinux' in k and k != 'alerts_selinux'])

    def test_api_ids_only_and_reader(self):
        self.asked = []
        self.look_both()
        d = E.Daemon(STORE, serve=False)
        fb = [f for f in E.selinux_view(STORE)['nodes'][1]['state']['findings'] if f['fixable']]
        with self.assertRaises(SystemExit):
            E.cli_api(d, 'tester', 'POST', '/api/selinux', {'node': 'acme-b', 'action': 'fix', 'ids': [fb[0]['id']],
                                                            'rule': '(allow httpd_t shadow_t (file (read)))'})
        got = E.cli_api(d, 'tester', 'POST', '/api/selinux', {'node': 'acme-b', 'action': 'fix', 'ids': [fb[0]['id']]})
        self.assertIn('acme-b puts right what was selected', got['message'])
        v = E.cli_api(d, 'tester', 'GET', '/api/selinux')
        self.assertEqual(v['nodes'][1]['pending'], 'fix')
        self.assertEqual(v['nodes'][1]['pending_ids'], [fb[0]['id']])

    def test_hand_and_alert_words(self):
        self.asked = []
        self.look_both()
        self.assertEqual(E.selinux_counts(STORE), (3, 0))
        items = E.hand_selinux_refuses(STORE)
        self.assertEqual(items[0]['id'], 'selinux-refuses')
        self.assertIn('SELinux refuses acme something - 3 can be put right on the card', items[0]['words'])
        self.assertEqual(items[0]['pane'], 'selinux')
        self.assertTrue(items[0]['cs']['words'])
        probs = E.selinux_problems(STORE)
        self.assertTrue(probs[0].startswith('SELinux refuses acme something - 3 can be put right on the card'))
        self.assertEqual(E.selinux_counts(STORE, 'acme-b'), (2, 0))


class CommandLine(Base):
    def helper_run(self, extra, want, timeout=600):
        """The root helper as the command line runs it - in-process, this machine's stand-in."""
        r = json.loads(want or '{}')
        if extra[0] == '--selinux-check':
            c = self.W.se_check(r)
            return SimpleNamespace(stdout=json.dumps(c) if '--json' in extra else self.W.se_report(c), stderr='', returncode=0)
        if extra[0] == '--selinux-do':
            self.sent.append(dict(r))
            try:
                c = self.W.se_do(dict(r, do=extra[1]))
            except self.W.Refused as e:
                return SimpleNamespace(stdout='', stderr=str(e), returncode=2)
            said = c.pop('said', [])
            return SimpleNamespace(stdout=json.dumps(dict(c, said=said)), stderr='', returncode=0)
        raise AssertionError(extra)

    def cli(self, *argv):
        self.sent = []
        args = E.build_parser().parse_args(list(argv))
        out = io.StringIO()
        want = json.dumps(WANT)
        with mock.patch.object(E.os, 'geteuid', return_value=0), \
                mock.patch.dict(E.cli_selinux.__globals__, {'_selinux_helper': self.helper_run,
                                                            '_selinux_after': lambda said: None}), \
                mock.patch.object(E.subprocess, 'run', return_value=SimpleNamespace(stdout=want, stderr='', returncode=0)), \
                mock.patch('sys.stdout', out):
            rc = E.cli_selinux(args, E.Palette(False))
        return rc, out.getvalue()

    def test_parser(self):
        p = E.build_parser()
        a = p.parse_args(['--selinux', 'enforce', '--yes'])
        self.assertEqual((a.selinux, a.selinux_more, a.yes), ('enforce', [], True))
        a = p.parse_args(['--selinux', 'fix', 'abcdefabcdef', '012345678901'])
        self.assertEqual((a.selinux, a.selinux_more), ('fix', ['abcdefabcdef', '012345678901']))
        a = p.parse_args(['--selinux', 'fix', '--all', '--yes'])
        self.assertTrue(a.all)
        a = p.parse_args(['--selinux', 'rules', '--take-away', 'abcdefabcdef'])
        self.assertEqual(a.take_away, 'abcdefabcdef')
        a = p.parse_args(['--selinux', 'report', '/root/x.tar.gz'])
        self.assertEqual(a.selinux_more, ['/root/x.tar.gz'])
        self.assertTrue(p.parse_args(['--selinux-check']).selinux_check)
        self.assertEqual(p.parse_args(['--selinux-report']).selinux_report, '')
        with mock.patch('sys.stderr', io.StringIO()):
            for bad in (['--selinux', 'reboot'], ['--selinux', 'enforce', 'now']):
                with self.assertRaises(SystemExit):
                    p.parse_args(bad)

    def test_look_fix_rules(self):
        rc, out = self.cli('--selinux', 'look')
        self.assertEqual(rc, 0)
        for words in ('A label (2)', "A rule of acme's (3)", 'Not for a button (10)', "Not acme's (2)",
                      'semanage port -a -t ssh_port_t -p tcp 2222', 'shadow_t is security-sensitive'):
            self.assertIn(words, out)
        ids = re.findall(r'^  ([0-9a-f]{12})  ', out, re.M)
        self.assertEqual(len(ids), 20)                                     # all but the one allowed now
        f = self.by_name(self.look())
        # Not for a button: refused before root is asked.
        with self.assertRaises(SystemExit) as e:
            self.cli('--selinux', 'fix', f['no_shadow']['id'], '--yes')
        self.assertIn('not for a button', str(e.exception))
        rc, out = self.cli('--selinux', 'fix', f['port_sshd']['id'], '--yes')
        self.assertEqual(rc, 0, out)
        self.assertIn('Root does exactly this on', out)
        self.assertIn('semanage port -a -t ssh_port_t -p tcp 2222', out)
        self.assertEqual(self.sent[0]['ids'], [f['port_sshd']['id']])
        self.assertEqual(set(self.sent[0]), {'ids', 'by'})                 # the ids alone
        rc, out = self.cli('--selinux', 'fix', '--all', '--yes')
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.sent[0]['ids']), 7)
        rc, out = self.cli('--selinux', 'rules')
        rids = re.findall(r'^([0-9a-f]{12})  \(allow', out, re.M)
        self.assertEqual(len(rids), 3)
        rc, out = self.cli('--selinux', 'rules', '--take-away', rids[0], '--yes')
        self.assertEqual(rc, 0)
        self.assertIn('taken away', out)
        self.assertEqual(len(self.W.se_local_read()), 2)
        with self.assertRaises(SystemExit):
            self.cli('--selinux', 'rules', '--take-away', 'abcdefabcdef', '--yes')
        rc, out = self.cli('--selinux', 'check')                           # as before
        self.assertIn('SELinux: Permissive', out)


class Module(unittest.TestCase):
    def test_pattern(self):
        cil = open(os.path.join(ROOT, 'deploy', 'acme_server.cil')).read()
        code = '\n'.join(x.split(';')[0] for x in cil.splitlines())
        self.assertEqual(code.count('('), code.count(')'))
        depth = 0
        for line in code.splitlines():
            if line.strip().startswith('(allow'):
                self.assertEqual(depth, 1, line)                        # each in its own optional block
            depth += line.count('(') - line.count(')')
        for t in ('ssh_t', 'ssh_keygen_t', 'ping_t', 'ifconfig_t', 'hostname_t', 'chronyc_t'):
            self.assertIn('(allow unconfined_service_t %s (process2 (nnp_transition nosuid_transition)))' % t, cil)
        self.assertIn('"/usr/libexec/keepalived/acme-vip-check" file', cil)
        self.assertIn('keepalived_unconfined_script_exec_t', cil)
        self.assertIn('(optional acme_server_postgresql_certs', cil)
        self.assertLess(code.index('(filecon "/run/acme"'), code.index('(optional'))      # labels first
        sh = open(os.path.join(ROOT, 'install.sh')).read()
        self.assertIn('semodule -r acme_local', sh)
        self.assertIn('semodule -r acme_server', sh)

    def test_secilc(self):
        sec, ref = os.environ.get('ACME_SECILC'), os.environ.get('ACME_REFPOLICY_CIL')
        if not sec or not ref:
            self.skipTest('no secilc and reference policy given (ACME_SECILC, ACME_REFPOLICY_CIL)')
        env = dict(os.environ)
        if os.environ.get('ACME_SECILC_LD'):
            env['LD_LIBRARY_PATH'] = os.environ['ACME_SECILC_LD']
        pol = sorted(os.path.join(ref, x) for x in os.listdir(ref) if x.endswith('.cil'))
        out = tempfile.mkdtemp()
        stub = os.path.join(out, 'stub.cil')
        with open(stub, 'w') as f:      # the RHEL types a reference policy does not have
            f.write('(type unconfined_service_t)\n(roletype system_r unconfined_service_t)\n'
                    '(type keepalived_t)\n(roletype system_r keepalived_t)\n'
                    '(type keepalived_unconfined_script_exec_t)\n(roletype object_r keepalived_unconfined_script_exec_t)\n')
        mod = os.path.join(ROOT, 'deploy', 'acme_server.cil')
        for extra in ([], [stub]):
            got = subprocess.run([sec, '-o', os.path.join(out, 'p'), '-f', os.path.join(out, 'fc')] + pol + extra + [mod],
                                 capture_output=True, text=True, env=env, timeout=600)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        with open(os.path.join(out, 'fc')) as f:
            fc = f.read()
        self.assertIn('/usr/libexec/keepalived/acme-vip-check', fc)
        self.assertRegex(fc, r'/run/acme\s+-d\s+system_u:object_r:httpd_(var_run|runtime)_t:s0')
        # A local module as root writes it, on top.
        local = os.path.join(out, 'acme_local.cil')
        with open(local, 'w') as f:
            f.write(W.se_local_text([{'id': '73f2d405a5f5', 'source': 'unconfined_service_t', 'target': 'chronyc_t',
                                      'class': 'process2', 'perms': ['nnp_transition'], 'program': 'acme', 'why': 'x', 'at': 0},
                                     {'id': '0330899ec3dc', 'source': 'chronyc_t', 'target': 'unconfined_service_t',
                                      'class': 'fifo_file', 'perms': ['write'], 'program': 'chronyc', 'why': 'y', 'at': 0}]))
        got = subprocess.run([sec, '-o', os.path.join(out, 'p'), '-f', os.path.join(out, 'fc')] + pol + [stub, mod, local],
                             capture_output=True, text=True, env=env, timeout=600)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def merge_cs(path, extra):
    """{English: Czech} added to a copy of web/lang/cs.json - a string, a pattern where it has {0},
    rich where it has a tag."""
    with open(path, encoding='utf-8') as f:
        pack = json.load(f)
    with open(extra, encoding='utf-8') as f:
        more = json.load(f)
    have = {v['source'] for sect in ('strings', 'patterns', 'rich') for v in pack.get(sect, {}).values()}
    i = 0
    for en, cs in more.items():
        if en in have:
            continue
        i += 1
        sect = 'patterns' if re.search(r'\{\d\}', en) else ('rich' if '<' in en else 'strings')
        pack.setdefault(sect, {})['%s8%04d' % (sect[0], i)] = {'source': en, 'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False, indent=1)


class Card(unittest.TestCase):
    """The card in Chromium: two nodes, the findings of each - English and Czech, 1400 and 390 px, an
    admin and a read-only account."""

    def test_card(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        tmp = tempfile.mkdtemp(prefix='acme-se-card-')
        for d in ('state', 'run', 'log'):
            os.makedirs(os.path.join(tmp, d))
        port = free_port()
        conf = os.path.join(tmp, 'config.json')
        with open(conf, 'w') as f:
            json.dump({'api_port': port, 'radius_bind': '127.0.0.1', 'radius_auth_port': free_port(),
                       'radius_acct_port': free_port(), 'ssh_gate_port': free_port(), 'node_name': 'acme-a',
                       'upgrade_check': 0}, f)
        env = dict(os.environ, ACME_CONFIG=conf, ACME_STATE=os.path.join(tmp, 'state'), ACME_RUN=os.path.join(tmp, 'run'),
                   ACME_LOGDIR=os.path.join(tmp, 'log'), ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        env.pop('ACME_NET_SNAP_DIR', None)
        pw = 'Test-Password-4711!'
        # What each node found: A permissive with some of everything (one rule of acme's put in, one
        # thing put right a moment ago), B enforcing with nothing open.
        hb = Base('run')
        hb.W = W
        hb.setUp()
        try:
            hb.m.avc = fixture([n for n in FIX if n not in ('no_err', 'no_constraint', 'no_generic', 'no_class')])
            c = hb.look()
            f = hb.by_name(c)
            done = W.se_do({'do': 'fix', 'ids': [f['port_sshd']['id'], f['rule_fifo']['id']], 'by': 'admin'})
            state_a = done
            said_a = done['said']
            hb.m.avc = fixture(['other_smbd'])
            hb.m.mode = 'Enforcing'
            state_b = hb.look()
        finally:
            hb.tearDown()
        made = subprocess.run([sys.executable, '-c', (
            'import sys, json, time; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); st.add_account("viewer", "readonly", %r); '
            'st.set_meta("node:acme-b", json.dumps({"at": time.time() + 86400})); '
            'st.set_meta("host:selinux:now:acme-a", json.dumps({"data": json.loads(%r), "at": time.time(), "done": "x", '
            '"said": json.loads(%r), "action": "fix", "by": "tester"})); '
            'st.set_meta("host:selinux:now:acme-b", json.dumps({"data": json.loads(%r), "at": time.time(), "done": "y", '
            '"said": [], "action": "check"}))') % (ROOT, pw, pw, json.dumps(state_a), json.dumps(said_a), json.dumps(state_b))],
            env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(made.returncode, 0, made.stderr[-2000:])
        daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=tmp)
        web = os.path.join(tmp, 'web')
        php = None
        try:
            end = time.time() + 60
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/api/health' % port, timeout=2)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            shutil.copytree(os.path.join(ROOT, 'web'), web)
            api_php = os.path.join(web, 'acme-api.php')
            with open(api_php, encoding='utf-8') as f:
                text = f.read()
            with open(api_php, 'w', encoding='utf-8') as f:
                f.write(text.replace('/run/acme/', os.path.join(tmp, 'run') + '/'))
            extra = os.environ.get('ACME_CS_EXTRA')
            if extra:
                merge_cs(os.path.join(web, 'lang', 'cs.json'), extra)
            wport = free_port()
            php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % wport], cwd=web, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % wport, timeout=2)
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'selinux_page.js'), 'http://127.0.0.1:%d' % wport, pw],
                                 capture_output=True, text=True, timeout=900, cwd=ROOT,
                                 env=dict(os.environ, ACME_SHOTS=os.environ.get('ACME_SHOTS', '')))
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            if php:
                php.terminate()
                php.wait(10)
            daemon.send_signal(signal.SIGTERM)
            try:
                daemon.wait(20)
            except subprocess.TimeoutExpired:
                daemon.kill()
        self.assertNotIn('error', seen, seen.get('error'))
        cs_merged = bool(extra) or '"Put in what is selected ({0})"' in open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8').read()
        for k, s in seen.items():
            self.assertEqual(s['errors'], [], k)
            self.assertLessEqual(s['overflow'], 0, k)
            self.assertIn('acme-b', s['card'])
            if k.startswith('en'):
                self.assertIn('What SELinux refuses', s['card'])
                self.assertIn('Not for a button', s['card'])
                self.assertIn("A rule of acme's", s['card'])
                self.assertIn('Put right just now', s['card'])
                self.assertIn("acme's local rules", s['card'])
            elif cs_merged:
                self.assertNotIn('What SELinux refuses', s['card'], k)
                self.assertNotIn('Not for a button', s['card'], k)
            if 'viewer' in k:
                self.assertEqual(s['buttons'], 0, k)
                self.assertEqual(s['checkboxes'], 0, k)
            else:
                self.assertGreater(s['checkboxes'], 3, k)
                self.assertTrue(s['put'], k)
        adm = seen['en1400tester']
        self.assertIn('Root does exactly this', adm['confirm'])
        self.assertIn('semanage port', adm['confirm'] + adm['card'])
        self.assertIn('ENFORCING', adm['node_b'].upper())
        self.assertTrue(adm['node_b_calm'])
        self.assertEqual(adm['cards'], 2)                                 # a card a node
        self.assertTrue(adm['side'])                                      # side by side at 1400 px
        for k, s in seen.items():
            if '390' in k:
                self.assertFalse(s['side'], k)                            # a phone: one under the other


if __name__ == '__main__':
    unittest.main()
