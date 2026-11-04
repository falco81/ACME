"""SELinux on the pages, the root helper, the command line (as otp 1.0.233 - 1.0.238).

    python3 test/test_selinux.py

- the root helper (deploy/acme_web.py): how SELinux stands (se_check) with the machine's
  commands played by the test - absent, disabled, permissive with something missing, ready;
  what was refused counted only since acme's needs were put in, and not what the policy loaded
  now allows (audit2why); auditd not running said and enforcing refused; a request
  (selinux.ask) answered in selinux.json; only the booleans and port types acme sets;
- the daemon: a step asked of a node, its card, the report kept sealed and given as one file,
  the security check and the alert (off by default);
- the pages: the card is drawn as otp draws it, the relay passes /api/selinux, every text of
  the card has its Czech; the module labels /run/acme and /var/run/acme; acme-web.path starts
  the helper for selinux.ask.
"""
import base64
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-selinux-')
os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def helper():
    spec = importlib.util.spec_from_file_location('acme_web_se', os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


W = helper()

AVC_OLD = ('type=AVC msg=audit(1000.100:11): avc:  denied  { read } for  pid=1 comm="php-fpm" '
           'name="api-token" scontext=system_u:system_r:httpd_t:s0 '
           'tcontext=system_u:object_r:var_run_t:s0 tclass=file permissive=1')
AVC_NEW = ('type=AVC msg=audit(%d.200:12): avc:  denied  { setattr } for  pid=1 comm="systemd" '
           'name="acme" scontext=system_u:system_r:init_t:s0 '
           'tcontext=system_u:object_r:httpd_var_run_t:s0 tclass=file permissive=1' % int(time.time()))


class Machine(object):
    """The commands of a machine with SELinux, as the helper runs them."""

    def __init__(self, mode='Permissive', module=True, boolean=True, avc=(), allowed=(), ports=''):
        self.mode, self.module, self.boolean = mode, module, boolean
        self.avc, self.allowed, self.ports = list(avc), set(allowed), ports
        self.ran = []

    def run(self, cmd, timeout=120, light=False, data=None):
        self.ran.append(list(cmd))
        r = lambda out='', rc=0, err='': SimpleNamespace(stdout=out, stderr=err, returncode=rc)  # noqa: E731
        if self.mode == 'absent':
            return None
        c = cmd[0]
        if c == 'getenforce':
            return r(self.mode + '\n')
        if c == 'semodule' and cmd[1:] == ['-l']:
            return r('acme_server\nbase\n' if self.module else 'base\n')
        if c == 'getsebool':
            return r('%s --> %s\n' % (cmd[1], 'on' if self.boolean else 'off'))
        if c == 'semanage' and cmd[1:3] == ['port', '-l']:
            return r(self.ports)
        if c == 'ausearch':
            return r('\n'.join(self.avc) + '\n')
        if c == 'audit2why':
            out = []
            for line in (data or '').splitlines():
                out.append(line)
                m = re.search(r'msg=audit\(([0-9.]+:\d+)\)', line)
                out.append('\tWas caused by:\n\t\tUnknown - would be allowed by active policy'
                           if m and m.group(1) in self.allowed else '\tWas caused by: missing type enforcement')
            return r('\n'.join(out) + '\n')
        if c == 'setenforce':
            self.mode = 'Enforcing' if cmd[1] == '1' else 'Permissive'
            return r()
        if c == 'setsebool':
            self.boolean = True
            return r()
        if c == 'restorecon':
            return r()
        if c == 'systemctl':
            return r('active\n')
        return r()


class TestHelper(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-se-h-')
        self.conf = os.path.join(self.d, 'config')
        with open(self.conf, 'w') as f:
            f.write('# SELinux\nSELINUX=permissive\nSELINUXTYPE=targeted\n')
        W.SE_CONFIG = self.conf
        W.SE_RELABEL = os.path.join(self.d, '.autorelabel')
        W.SE_CMDLINE = os.path.join(self.d, 'cmdline')
        with open(W.SE_CMDLINE, 'w') as f:
            f.write('ro quiet\n')
        W.SE_CIL = os.path.join(self.d, 'acme_server.cil')
        os.environ['ACME_SELINUX_AUDITD'] = 'active'
        self.had_which = W.shutil.which
        W.shutil.which = lambda c: None if c in ('restorecon', 'grubby') else '/usr/bin/' + c
        # acme's files labelled as the policy wants, wherever they are here.
        labels = os.path.join(self.d, 'labels.json')
        with open(labels, 'w') as f:
            json.dump({p: want for p, want, _why in W.SE_LABELS}, f)
        os.environ['ACME_SELINUX_LABELS'] = labels
        W.WEB_DIR = os.path.join(TMP, 'web')
        try:
            os.unlink(os.path.join(TMP, 'web', W.SE_APPLIED))
        except OSError:
            pass

    def tearDown(self):
        W.shutil.which = self.had_which
        os.environ.pop('ACME_SELINUX_AUDITD', None)
        os.environ.pop('ACME_SELINUX_LABELS', None)

    def machine(self, **kw):
        m = Machine(**kw)
        W._se_run = m.run
        return m

    def test_absent(self):
        self.machine(mode='absent')
        c = W.se_check({})
        self.assertEqual(c['mode'], 'absent')
        self.assertFalse(c['ready'])
        self.assertIn('no SELinux on this machine', W.se_report(c))

    def test_disabled_says_nothing_wrong(self):
        self.machine(mode='Disabled')
        c = W.se_check({})
        self.assertEqual(c['problems'], [])
        self.assertFalse(c['ready'])

    def test_permissive_ready(self):
        self.machine(boolean=True)
        c = W.se_check({'booleans': [{'name': 'httpd_can_network_connect', 'why': 'x'}]})
        self.assertEqual(c['problems'], [], c)
        self.assertTrue(c['ready'])

    def test_missing_said(self):
        self.machine(module=False, boolean=False, avc=[AVC_NEW])
        c = W.se_check({'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages'}]})
        words = ' | '.join(c['problems'])
        self.assertIn("acme's module (acme_server) is not installed", words)
        self.assertIn('the boolean httpd_can_network_connect is off', words)
        self.assertIn('SELinux refused 1 thing(s) since the machine started', words)
        self.assertFalse(c['ready'])

    def test_refused_before_the_needs_went_in_does_not_count(self):
        self.machine(avc=[AVC_OLD])
        W.write_here(W.SE_APPLIED, json.dumps({'at': 2000}))
        c = W.se_check({})
        self.assertEqual(c['denials']['total'], 0)
        self.assertTrue(c['ready'])

    def test_allowed_now_is_not_counted(self):
        self.machine(avc=[AVC_NEW], allowed=[re.search(r'audit\(([0-9.]+:\d+)\)', AVC_NEW).group(1)])
        c = W.se_check({})
        self.assertEqual(c['denials']['total'], 0)
        self.assertEqual(c['denials']['settled'], 1)
        self.assertIn('refused before, allowed now (not counted): 1', W.se_report(c))

    def test_auditd_not_running_refuses_enforcing(self):
        self.machine()
        os.environ['ACME_SELINUX_AUDITD'] = 'inactive'
        c = W.se_check({})
        self.assertTrue(any('auditd does not run' in p for p in c['problems']))
        with self.assertRaises(W.Refused):
            W.se_do({'do': 'enforce'})

    def test_enforce_from_permissive(self):
        m = self.machine()
        c = W.se_do({'do': 'enforce'})
        self.assertEqual(m.mode, 'Enforcing')
        self.assertIn('SELINUX=enforcing', open(self.conf).read())
        self.assertIn('SELinux is enforcing, and stays so after a restart', c['said'])
        with self.assertRaises(W.Refused):
            W.se_do({'do': 'enforce'})              # from permissive only

    def test_prepare_from_disabled(self):
        self.machine(mode='Disabled')
        with open(self.conf, 'w') as f:
            f.write('SELINUX=disabled\n')
        c = W.se_do({'do': 'prepare'})
        self.assertIn('SELINUX=permissive', open(self.conf).read())
        self.assertTrue(os.path.exists(W.SE_RELABEL))
        self.assertTrue(any('restart the machine' in s for s in c['said']))

    def test_only_what_acme_sets(self):
        self.machine()
        with self.assertRaises(W.Refused):
            W.se_check({'booleans': [{'name': 'authlogin_radius'}]})
        with self.assertRaises(W.Refused):
            W.se_check({'ports': [{'port': 1812, 'proto': 'udp', 'type': 'radius_port_t'}]})
        with self.assertRaises(W.Refused):
            W.se_check({'ports': [{'port': 99999, 'proto': 'tcp', 'type': 'ssh_port_t'}]})

    def test_port_of_another_service_never_taken(self):
        m = self.machine()

        def run(cmd, timeout=120, light=False, data=None):
            if cmd[:3] == ['semanage', 'port', '-a']:
                return SimpleNamespace(stdout='', stderr='ValueError: Port tcp/443 already defined',
                                       returncode=1)
            return Machine.run(m, cmd, timeout, light, data)
        W._se_run = run
        with self.assertRaises(W.Refused) as e:
            W.se_do({'do': 'prepare', 'ports': [{'port': 443, 'proto': 'tcp', 'type': 'ssh_port_t',
                                                 'why': 'the SSH server listens on it'}]})
        self.assertIn("another service's", str(e.exception))

    def test_request_answered(self):
        self.machine()
        with open(os.path.join(TMP, 'web', 'selinux.ask'), 'w') as f:
            f.write(json.dumps({'id': 'abc123', 'do': 'check'}))
        W.FD[0] = None
        W.selinux_part()
        got = json.load(open(os.path.join(TMP, 'web', 'selinux.json')))
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['id'], 'abc123')
        self.assertEqual(got['data']['mode'], 'Permissive')
        self.assertFalse(os.path.exists(os.path.join(TMP, 'web', 'selinux.ask')))

    def test_report_is_a_tar_with_its_parts(self):
        self.machine()
        data = W.se_report_bytes({'facts': {'acme': '1'}}, 'node1')
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
        for part in ('check.json', 'acme.json', 'avc.txt', 'labels.txt', 'README.txt'):
            self.assertIn('node1/' + part, names)


class TestDaemon(unittest.TestCase):
    def test_ask_and_view(self):
        E.selinux_ask(STORE, E.node_name(), 'prepare', 'admin')
        v = E.selinux_view(STORE)
        me = [n for n in v['nodes'] if n['me']][0]
        self.assertEqual(me['pending'], 'prepare')
        with self.assertRaises(ValueError):
            E.selinux_ask(STORE, 'nobody', 'check', 'admin')
        with self.assertRaises(ValueError):
            E.selinux_ask(STORE, E.node_name(), 'reboot', 'admin')

    def test_want_has_no_radius(self):
        w = E.selinux_want(STORE)
        self.assertEqual([b['name'] for b in w['booleans']], ['httpd_can_network_connect'])
        self.assertTrue(all(p['type'] in ('ssh_port_t', 'postgresql_port_t') for p in w['ports']))
        self.assertIn('acme', w['facts'])

    def test_problems_security_check_and_alert(self):
        STORE.set_meta('host:selinux:now:' + E.node_name(), json.dumps({
            'data': {'mode': 'Permissive', 'problems': ["acme's module (acme_server) is not installed"]},
            'at': time.time()}))
        self.assertEqual(E.selinux_problems(STORE), ["acme's module (acme_server) is not installed"])
        warn = [w['what'] for w in E.hisec_findings(STORE).get('warn', [])]
        self.assertTrue(any(w.startswith('SELinux on %s:' % E.node_name()) for w in warn), warn)
        self.assertEqual(E.DEFAULTS['alerts_selinux'], 0)
        E.CONFIG['alerts_selinux'] = 0
        self.assertFalse([k for k in E.alert_problems(STORE) if k.startswith('selinux:')])
        E.CONFIG['alerts_selinux'] = 1
        try:
            got = [k for k in E.alert_problems(STORE) if k.startswith('selinux:')]
        finally:
            E.CONFIG['alerts_selinux'] = 0
        self.assertEqual(len(got), 1)
        # Permissive with nothing missing: said in the security check, never mailed.
        STORE.set_meta('host:selinux:now:' + E.node_name(), json.dumps({
            'data': {'mode': 'Permissive', 'problems': []}, 'at': time.time()}))
        self.assertTrue(E.selinux_problems(STORE))
        E.CONFIG['alerts_selinux'] = 1
        try:
            self.assertFalse([k for k in E.alert_problems(STORE) if k.startswith('selinux:')])
        finally:
            E.CONFIG['alerts_selinux'] = 0
        STORE.set_meta('host:selinux:now:' + E.node_name(), json.dumps({'data': {'mode': 'Disabled'}}))
        self.assertEqual(E.selinux_problems(STORE), [])

    def test_report_sealed_and_bundled(self):
        raw = b'a report'
        STORE.set_meta('host:selinux:report:' + E.node_name(), json.dumps({
            'id': 'x', 'at': time.time(), 'error': '', 'bytes': len(raw),
            'data': E.seal_secret(base64.b64encode(raw).decode('ascii'), 'selinux:report')}))
        self.assertNotIn('a report', STORE.get_meta('host:selinux:report:' + E.node_name()))
        data, missing = E.selinux_report_bundle(STORE)
        self.assertEqual(missing, [])
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            names = tf.getnames()
            inner = tf.extractfile('acme-selinux-report-%s.tar.gz' % E.node_name()).read()
        self.assertEqual(inner, raw)
        self.assertIn('README.txt', names)
        # An hour old: taken out of the database.
        STORE.set_meta('host:selinux:report:' + E.node_name(), json.dumps({'at': time.time() - 4000}))
        E.selinux_report_tidy(STORE)
        self.assertIsNone(STORE.get_meta('host:selinux:report:' + E.node_name()))

    def test_command_line_knows_it(self):
        parser = E.build_parser()
        a = parser.parse_args(['--selinux', 'enforce', '--yes'])
        self.assertEqual(a.selinux, 'enforce')
        a = parser.parse_args(['--selinux-report'])
        self.assertEqual(a.selinux_report, '')
        self.assertTrue(parser.parse_args(['--selinux-check']).selinux_check)


class TestPagesAndFiles(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
            return f.read()

    def test_the_card(self):
        js, php, css = (self.read('web', 'assets', 'admin.js'), self.read('web', 'admin', 'index.php'),
                        self.read('web', 'assets', 'acme.css'))
        self.assertEqual(len(re.findall(r"'selinux' => '/api/selinux'", php)), 2)
        self.assertLess(php.index('id="hs-host"'), php.index('id="se-host"'))
        for piece in ('function loadSelinux(', 'function drawSelinux(', 'function seNode(',
                      'function seReport(', "api('selinux', {action: 'download'})", 'loadSelinux();'):
            self.assertIn(piece, js)
        for piece in ('.se-grid{', '.se-node{', '.se-verdict.ready{', '.se-avc-t td.num{'):
            self.assertIn(piece, css)
        self.assertFalse(re.search(r'(?<!as )\botp\b', js[js.index('var SE = {'):]))
        self.assertNotIn('RADIUS', js[js.index('var SE = {'):])

    def test_every_text_of_the_card_in_czech(self):
        js = self.read('web', 'assets', 'admin.js')
        block = js[js.index('var SE = {'):]
        cs = json.loads(self.read('web', 'lang', 'cs.json'))
        src = {v['source'] for sec in ('strings', 'patterns', 'rich') for v in cs[sec].values()}
        missing = []
        for m in re.finditer(r"(?:el\([^,]+, '[^']*', |cmdButton\(|seRow\(list, [^,]+, |words: |confirmThen\(|htmlText\()'((?:[^'\\]|\\.)+)'", block):
            w = m.group(1).replace("\\'", "'").strip()
            follows = block[m.end():m.end() + 4].lstrip()
            if follows.startswith('+'):
                if any(k.startswith(w) and '{0}' in k for k in src):
                    continue
            if w and not re.match(r'^[\W\d]*$', w) and w not in src:
                missing.append(w)
        self.assertEqual(missing, [])

    def test_module_and_units(self):
        cil = self.read('deploy', 'acme_server.cil')
        for path in ('"/run/acme"', '"/var/run/acme"', '"/run/acme/.*"', '"/var/run/acme/.*"'):
            self.assertIn(path, cil)
        self.assertIn('(allow init_t httpd_var_run_t (file (getattr setattr)))', cil)
        self.assertFalse(re.search(r'(?<!as )\botp\b', cil))
        self.assertIn('PathExists=/var/lib/acme/web/selinux.ask', self.read('deploy', 'acme-web.path'))
        sh = self.read('install.sh')
        for piece in ('selinux_module\n', 'semodule -r acme_server', 'acme_server.cil.in-policy',
                      'policycoreutils-python-utils', 'systemctl enable --now auditd'):
            self.assertIn(piece, sh)


if __name__ == '__main__':
    unittest.main()
