#!/usr/bin/env python3
"""What happens - the run plan of a certificate (acmelib/certs/runplan.py), through
a real daemon (the helpers of test_certs_core).

    python3 test/test_plan.py

A certificate from an authority of acme's own and one from an ACME source proved
by Webglobe and Cloudflare (secrets set), deployed to this machine's files, a
server over SSH and a NetScaler - every host the fake one 127.0.0.1:<a port a
listening server holds>. The plan lists the calls, commands and paths expected,
holds none of the secrets and no private key - and the listening server sees no
connection at all, the folder of the files stays empty.
"""
import json
import os
import socket
import sys
import threading
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_certs_core as core  # noqa: E402

SECRETS = {'ns': 'Ns-Pass-Very-Secret-0001', 'ssh': 'Ssh-Pass-Very-Secret-0002',
           'sudo': 'Sudo-Pass-Very-Secret-0003', 'wg': 'WgApiKeyVerySecret0004',
           'cf': 'CfTokenVerySecret0005xyz', 'pfx': 'Pfx-Pass-Very-Secret-0006'}


class Listener(object):
    """A server that must see nobody: every connection it accepts is counted."""
    def __init__(self):
        self.s = socket.socket()
        self.s.bind(('127.0.0.1', 0))
        self.s.listen(16)
        self.port = self.s.getsockname()[1]
        self.seen = 0
        self.stop = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        self.s.settimeout(0.3)
        while not self.stop:
            try:
                c, _a = self.s.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.seen += 1
            c.close()
        self.s.close()


class Plan(core.CertsCore):
    @classmethod
    def setUpClass(cls):
        core.CertsCore.setUpClass()
        cls.listener = Listener()

    @classmethod
    def tearDownClass(cls):
        cls.listener.stop = True
        core.CertsCore.tearDownClass()

    def setup_world(self):
        if getattr(type(self), 'made', None):
            return type(self).made
        port = self.listener.port
        out = os.path.join(self.tmp, 'plan-out')
        self.ok('POST', '/api/cas/create', {'name': 'Plan Root', 'subject': {'CN': 'Plan Root'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Plan Root', 'days': 90}})
        self.ok('POST', '/api/validations/save', {'name': 'wg', 'kind': 'webglobe', 'config': {
            'login': 'me@example.cz', 'auth': 'token', 'api_token': SECRETS['wg'],
            'api': 'http://127.0.0.1:%d' % port, 'zone': 'example.cz'}})
        self.ok('POST', '/api/validations/save', {'name': 'cf', 'kind': 'cloudflare', 'config': {
            'token': SECRETS['cf'], 'api': 'http://127.0.0.1:%d/client/v4' % port,
            'zone_id': 'zone123'}})
        self.ok('POST', '/api/targets/save', {'name': 'files', 'kind': 'local', 'config': {
            'base': out}})
        self.ok('POST', '/api/targets/save', {'name': 'web', 'kind': 'ssh', 'config': {
            'host': '127.0.0.1', 'port': port, 'user': 'deploy', 'auth': 'password',
            'password': SECRETS['ssh'], 'sudo': True, 'sudo_password': SECRETS['sudo']}})
        self.ok('POST', '/api/targets/save', {'name': 'adc', 'kind': 'netscaler', 'config': {
            'host': '127.0.0.1', 'port': port, 'user': 'nsroot', 'password': SECRETS['ns'],
            'verify_tls': False}})
        ids = {}
        for name, issuer, extra in (('plan-own', 'own', {}),
                                    ('plan-acme', 'LetsEncrypt staging',
                                     {'challenge': 'wg',
                                      'challenge_map': {'shop.example.com': 'cf'}})):
            ids[name] = self.ok('POST', '/api/certs/save', dict({
                'name': name, 'names': ['www.example.cz', 'shop.example.com'], 'issuer': issuer,
                'auto_renew': 0, 'key_type': 'ec-256'}, **extra))['id']
            for t, opts in (('files', {'outputs': ['fullchain-pem {name}/fullchain.pem',
                                                   'key-pem {name}/privkey.pem 0600',
                                                   'pfx {name}/site.pfx'],
                                       'pfx_password_mode': 'fixed',
                                       'pfx_password': SECRETS['pfx']}),
                            ('web', {'outputs': ['fullchain-pem /etc/nginx/ssl/site.pem',
                                                 'key-pem /etc/nginx/ssl/site.key 0600'],
                                     'reload_cmd': ['systemctl reload nginx'],
                                     'verify': ['127.0.0.1:%d' % port]}),
                            ('adc', {'certkey': 'www_cert', 'vservers': ['vs_www', 'vs_mail sni'],
                                     'verify': ['127.0.0.1:%d' % port]})):
                self.ok('POST', '/api/deploys/save', {'cert_id': ids[name], 'target': t,
                                                      'options': opts, 'enabled': True})
        type(self).made = (ids, out)
        return type(self).made

    def plan_of(self, cid, session=None):
        return self.ok('GET', '/api/certs/run_plan', args={'id': cid}, session=session)['plan']

    def no_secrets(self, plan):
        text = json.dumps(plan, ensure_ascii=False)
        for k, v in SECRETS.items():
            self.assertNotIn(v, text, 'the secret of %s is in the plan' % k)
        self.assertNotIn('PRIVATE KEY', text)
        self.assertNotIn('plansecret', text)
        self.assertNotIn('cGxhbnNlY3JldD', text)

    def all_steps(self, phase):
        out = list(phase.get('steps') or [])
        for g in phase.get('groups') or []:
            out += g.get('steps') or []
            for p in g.get('per_name') or []:
                out += p.get('steps') or []
        return out

    def test_49_tests_and_guides_shown(self):
        """1.0.95: each deployment says whether a test checks what it serves; a test acme made
        from a deployment says so, and how many times it asks; each module carries its
        family and version (its setup guide)."""
        ids, out = self.setup_world()
        plan = self.plan_of(ids['plan-own'])
        ph = {p['key']: p for p in plan['phases']}
        groups = {g['title']: g for g in ph['deploy']['groups']}
        words = [s['words'] for s in groups['web']['steps']]
        self.assertIn('What it serves is checked by the tests attached', words)
        self.assertEqual(groups['web']['module']['family'], 'target')
        self.assertIn('version', groups['web']['module'])
        self.assertEqual(ph['source']['module']['family'], 'issuer')
        tsteps = [s['words'] for s in self.all_steps(ph['checks'])]
        self.assertIn('Made by acme from a deployment: what the target serves', tsteps)
        self.assertTrue(any(w.startswith('Asked ') for w in tsteps), tsteps)
        self.assertTrue(all(g['module']['family'] == 'check' for g in ph['checks']['groups']
                            if g.get('module')))

    def test_50_own_ca_plan(self):
        ids, out = self.setup_world()
        plan = self.plan_of(ids['plan-own'])
        self.no_secrets(plan)
        ph = {p['key']: p for p in plan['phases']}
        self.assertEqual(list(ph), ['key', 'source', 'validation', 'deploy', 'checks', 'after'])
        self.assertIn('A new ec-256 key is made here, on this machine',
                      [s['words'] for s in ph['key']['steps']])
        src = json.dumps(ph['source'], ensure_ascii=False)
        self.assertIn('Plan Root', src)
        groups = {g['title']: g for g in ph['deploy']['groups']}
        self.assertEqual(set(groups), {'files', 'web', 'adc'})
        # NetScaler: NITRO, in order
        ns = groups['adc']['steps']
        urls = [(s['detail'].get('method'), s['detail'].get('url')) for s in ns
                if (s.get('detail') or {}).get('url')]
        base = 'https://127.0.0.1:%d/nitro/v1/config/' % self.listener.port
        want = [('POST', base + 'login'), ('POST', base + 'systemfile'),
                ('POST', base + 'sslcertkey'), ('POST', base + 'sslcertkey?action=update'),
                ('PUT', base + 'sslvserver_sslcertkey_binding'),
                ('POST', base + 'nsconfig?action=save'), ('POST', base + 'logout')]
        for w in want:
            self.assertIn(w, urls)
        login = [s for s in ns if (s.get('detail') or {}).get('url') == base + 'login'][0]
        self.assertEqual(login['detail']['body']['login']['username'], 'nsroot')
        self.assertTrue(login['detail']['body']['login']['password'].startswith('•'))
        branches = {s['detail']['url']: s.get('branch') for s in ns
                    if (s.get('detail') or {}).get('url', '').endswith(('sslcertkey',
                                                                        'action=update'))}
        self.assertIn('first', branches[base + 'sslcertkey'])
        self.assertIn('later', branches[base + 'sslcertkey?action=update'])
        up = [s for s in ns if (s.get('detail') or {}).get('url') == base + 'systemfile']
        self.assertTrue(any('private key' in json.dumps(s['detail']['body']) for s in up))
        # "Check what is served" is a test of the target now (1.0.77): in the tests' phase
        hosts = [g.get('host') for g in ph['checks']['groups']]
        self.assertIn('127.0.0.1:%d' % self.listener.port, hosts)
        # SSH: the connection, the files, the reload
        ssh = groups['web']['steps']
        cmds = '\n'.join((s.get('detail') or {}).get('command') or '' for s in ssh)
        self.assertIn('systemctl reload nginx', cmds)
        self.assertIn('/etc/nginx/ssl/site.key', cmds)
        conn = [s for s in ssh if s['kind'] == 'connect'][0]
        self.assertIn('deploy@127.0.0.1', conn['words'])
        files = [s for s in ssh if s['words'] == 'The files it writes'][0]['detail']['files']
        self.assertEqual([f['path'] for f in files], ['/etc/nginx/ssl/site.pem',
                                                      '/etc/nginx/ssl/site.key'])
        self.assertTrue(any('sudo' in (s.get('note') or '') for s in ssh))
        # this machine: the paths under its folder, nothing written
        loc = groups['files']['steps']
        paths = [(s.get('detail') or {}).get('path') for s in loc if s['kind'] == 'file']
        self.assertIn(os.path.join(out, 'plan-own/privkey.pem'), paths)
        self.assertIn(os.path.join(out, 'plan-own/site.pfx'), paths)
        self.assertFalse(os.path.exists(out), 'the plan made the folder of the files')
        self.assertEqual(self.listener.seen, 0)

    def test_51_acme_plan_with_validations(self):
        ids, out = self.setup_world()
        plan = self.plan_of(ids['plan-acme'])
        self.no_secrets(plan)
        ph = {p['key']: p for p in plan['phases']}
        src = json.dumps(ph['source'], ensure_ascii=False)
        self.assertIn('https://acme-staging-v02.api.letsencrypt.org/directory', src)
        self.assertIn('newOrder', src.replace('new-order', 'newOrder'))
        self.assertIn('"identifiers"', src)
        groups = {g['title']: g for g in ph['validation']['groups']}
        self.assertEqual(set(groups), {'wg', 'cf'})
        self.assertEqual(groups['wg']['names'], ['www.example.cz'])
        # 1.0.98: the ACME exchange recorded, each name's validation within it (the source
        # shows its calls); the validation phase says so
        self.assertIn('Recorded against a stand-in of the CA', src)
        self.assertIn('http://127.0.0.1:%d/auth/login' % self.listener.port, src)
        self.assertIn('_acme-challenge', src)
        self.assertIn('/zones/zone123/dns_records', src)
        self.assertNotIn(SECRETS['cf'], src)
        self.assertNotIn(SECRETS['wg'], src)
        for g in groups.values():
            self.assertIn('within the source\'s run', g['steps'][0]['words'])
        self.assertEqual(self.listener.seen, 0)
        self.assertFalse(os.path.exists(out))

    def test_52_readonly_and_draft(self):
        ids, out = self.setup_world()
        plan = self.plan_of(ids['plan-own'], session=self.ro)
        self.no_secrets(plan)
        got = self.ok('POST', '/api/certs/run_plan', {'draft': {
            'names': ['draft.example.cz'], 'issuer': 'own', 'key_type': 'rsa-2048',
            'deploys': {'adc': {'certkey': 'draft_ck', 'password': 'x'}}}})['plan']
        self.no_secrets(got)
        self.assertTrue(got['cert']['draft'])
        self.assertIn('draft_ck', json.dumps(got))
        self.assertIn('A new rsa-2048 key is made here, on this machine',
                      [s['words'] for s in got['phases'][0]['steps']])
        n = self.call('GET', '/api/certs', session=self.admin)[1]
        self.assertNotIn('draft.example.cz', json.dumps(n))     # nothing saved
        self.assertEqual(self.listener.seen, 0)

    def test_52b_subject_checked_as_the_csr_will_have_it(self):
        """Hunt M: a subject with C "Czech Republic" or an e-mail that is none was saved, and
        What happens drew a CSR with it - every renewal then failed. Refused by the save and
        the draft alike, in words; a right one is kept (C in capitals)."""
        self.setup_world()
        base = {'names': ['subj.example.cz'], 'issuer': 'own', 'auto_renew': 0}
        for subj, words in (({'C': 'Czech Republic'}, 'two letters'),
                            ({'emailAddress': 'notanemail'}, 'not a mail address'),
                            ({'O': 'x' * 65}, '64 characters'),
                            ({'OU': 'a\nb'}, 'control characters'),
                            ({'O': {'x': 1}}, 'is words'),
                            ({'Bad Field!': 'x'}, 'unknown subject field')):
            st, got = self.call('POST', '/api/certs/save', dict(base, name='subj-bad',
                                                                 profile={'subject': subj}),
                                session=self.admin)
            self.assertEqual(st, 400, (subj, got))
            self.assertIn(words, json.dumps(got), subj)
            st, got = self.call('POST', '/api/certs/run_plan', {'draft': dict(
                base, profile={'subject': subj})}, session=self.admin)
            self.assertEqual(st, 400, (subj, got))
            self.assertIn(words, json.dumps(got), subj)
        n = self.call('GET', '/api/certs', session=self.admin)[1]
        self.assertNotIn('subj-bad', json.dumps(n))
        cid = self.ok('POST', '/api/certs/save', dict(base, name='subj-good', profile={'subject': {
            'C': 'cz', 'O': 'Example s.r.o.', 'OU': ['IT', 'Web'],
            'emailAddress': 'it@example.cz'}}))['id']
        prof = self.ok('GET', '/api/certs/one', args={'id': cid})['cert'].get('profile')
        subj = (json.loads(prof) if isinstance(prof, str) else prof or {}).get('subject')
        self.assertEqual(subj, {'C': 'CZ', 'O': 'Example s.r.o.', 'OU': ['IT', 'Web'],
                                'emailAddress': 'it@example.cz'})
        plan = self.ok('POST', '/api/certs/run_plan', {'draft': dict(
            base, profile={'subject': {'C': 'cz', 'O': 'Example'}})})['plan']
        self.assertTrue(plan['cert']['draft'])

    def test_52c_subject_saved_before_kept(self):
        """Hunt M round 3 (1.0.101): RFC 5280's lengths (L and ST 128, the e-mail 255, the
        rest 64), an e-mail without a dot in its domain; and a subject saved before that the
        check refuses (it renews: pki makes its CSR) does not block every later save and plan
        of the certificate - the page sends the profile back. Given or changed, it is checked."""
        self.setup_world()
        base = {'names': ['subj3.example.cz'], 'issuer': 'own', 'auto_renew': 0}
        cid = self.ok('POST', '/api/certs/save', dict(base, name='subj3', profile={'subject': {
            'L': 'L' * 128, 'ST': 'S' * 128, 'O': 'O' * 64, 'OU': 'U' * 64,
            'emailAddress': 'pki@corp'}}))['id']
        for subj, words in (({'L': 'L' * 129}, '128 characters'),
                            ({'ST': 'S' * 129}, '128 characters'),
                            ({'O': 'O' * 65}, '64 characters'),
                            ({'OU': 'U' * 65}, '64 characters'),
                            ({'emailAddress': 'pki corp@x'}, 'not a mail address'),
                            ({'emailAddress': 'no-at-sign'}, 'not a mail address')):
            st, got = self.call('POST', '/api/certs/save', {'id': cid, 'profile': {
                'subject': subj}}, session=self.admin)
            self.assertEqual(st, 400, (subj, got))
            self.assertIn(words, json.dumps(got), subj)
        # saved before the check (or by an older version): the C of a whole word
        old = {'C': 'Czech Republic', 'ST': 'S' * 150, 'emailAddress': 'notanemail'}
        self.py('import json as J; r = st.db.row("SELECT profile FROM certs WHERE id = %d"); '
                'p = J.loads(r["profile"] or "{}"); p["subject"] = %r; '
                'st.db.run("UPDATE certs SET profile = ? WHERE id = %d", (J.dumps(p),)); '
                'print(1)' % (cid, old, cid))
        prof = self.ok('GET', '/api/certs/one', args={'id': cid})['cert'].get('profile')
        prof = json.loads(prof) if isinstance(prof, str) else prof
        self.assertEqual(prof['subject'], old)
        self.ok('POST', '/api/certs/save', {'id': cid, 'profile': prof, 'renew_days': 20})
        self.ok('POST', '/api/certs/run_plan', {'id': cid, 'draft': dict(base, profile=prof)})
        st, got = self.call('POST', '/api/certs/save', {'id': cid, 'profile': dict(
            prof, subject=dict(old, O='x'))}, session=self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/certs/run_plan', {'id': cid, 'draft': dict(
            base, profile=dict(prof, subject=dict(old, O='x')))}, session=self.admin)
        self.assertEqual(st, 400, got)

    def test_53_own_pages_as_they_are(self):
        """1.0.98: a deployment to acme's own pages is recorded with the nodes and what their
        pages hold now (runplan.pages_of) - not a made-up node."""
        ids, out = self.setup_world()
        self.ok('POST', '/api/targets/save', {'name': 'pages', 'kind': 'appliance',
                                              'config': {}})
        self.ok('POST', '/api/deploys/save', {'cert_id': ids['plan-own'], 'target': 'pages',
                                              'options': {'where': 'this'}, 'enabled': True})
        plan = self.plan_of(ids['plan-own'])
        self.no_secrets(plan)
        ph = {p['key']: p for p in plan['phases']}
        groups = {g['title']: g for g in ph['deploy']['groups']}
        words = ' | '.join(str(s.get('words')) for s in groups['pages']['steps'])
        self.assertIn('the pages of ', words)
        self.assertNotIn('the pages of acme ', words)       # the sandbox's own stand-in node
        self.assertIn("Puts it into acme's own pages", words)


class Lockdown(unittest.TestCase):
    """The recording's process (plansandbox.lockdown) fails closed: what no
    recording catches - a socket, a program, a file outside its folder - raises."""

    def test_nothing_gets_out(self):
        import subprocess
        import tempfile
        folder = tempfile.mkdtemp(prefix='acme-plan-test-')
        outside = tempfile.mkdtemp(prefix='acme-plan-outside-')
        lst = Listener()
        code = r"""
import sys, os, socket, subprocess, json
sys.path.insert(0, %r)
from acmelib.certs import plansandbox as m
m.lockdown(%r)
got = {}
def tryit(k, fn):
    try:
        fn(); got[k] = 'done'
    except Exception as e:
        got[k] = type(e).__name__
tryit('connect', lambda: socket.create_connection(('127.0.0.1', %d), 2))
tryit('socket', lambda: socket.socket().connect(('127.0.0.1', %d)))
tryit('dns', lambda: socket.getaddrinfo('example.com', 443))
tryit('program', lambda: subprocess.run(['true']))
tryit('s_client', lambda: subprocess.run(['openssl', 's_client', '-connect', '127.0.0.1:%d']))
tryit('write', lambda: open(os.path.join(%r, 'x'), 'w').write('x'))
tryit('mkdir', lambda: os.mkdir(os.path.join(%r, 'd')))
tryit('inside', lambda: open(os.path.join(%r, 'ok'), 'w').write('x'))
print(json.dumps(got))
""" % (core.ROOT, folder, lst.port, lst.port, lst.port, outside, outside, folder)
        r = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True,
                           timeout=60, env={'PATH': os.environ.get('PATH', ''),
                                            'TMPDIR': folder})
        got = json.loads(r.stdout.strip().splitlines()[-1])
        for k in ('connect', 'socket', 'dns', 'program', 's_client', 'write', 'mkdir'):
            self.assertEqual(got[k], 'Blocked', '%s: %s' % (k, got))
        self.assertEqual(got['inside'], 'done')
        self.assertEqual(os.listdir(outside), [])
        lst.stop = True
        self.assertEqual(lst.seen, 0)


for _n in dir(core.CertsCore):
    if _n.startswith('test_'):
        setattr(Plan, _n, None)


class EncodedPowerShell(unittest.TestCase):
    """1.0.23: powershell -EncodedCommand shown readable, its stand-ins masked."""

    def test_decoded(self):
        import base64
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from acmelib.certs import plansandbox as PS
        script = ("$pw = 'STANDIN-SECRET'\r\nImport-PfxCertificate -FilePath C:\\x.pfx\r\n"
                  "$s = ConvertTo-SecureString -String 'made-for-the-run' -AsPlainText -Force")
        cmd = 'powershell.exe -NoProfile -EncodedCommand ' + base64.b64encode(
            script.encode('utf-16-le')).decode()
        self.assertIn('Import-PfxCertificate', PS.encoded_script(cmd))
        self.assertNotIn('\r', PS.encoded_script(cmd))
        self.assertEqual(PS.encoded_script('nginx -t'), '')
        masked = PS.mask_text(PS.encoded_script(cmd), {'STANDIN-SECRET': 'the password'})
        self.assertNotIn('STANDIN-SECRET', masked)
        self.assertNotIn('made-for-the-run', PS.encoded_script(cmd))


class TestOwnConnections(unittest.TestCase):
    """What happens (1.0.37): a module that opens its connections itself - http.client
    or urllib, ftplib, a socket of its own - is recorded too, its secrets left out."""
    def test_recorded(self):
        import subprocess
        code = r"""
import io, json, socket, ssl, sys, urllib.request, ftplib
sys.path.insert(0, %r)
from acmelib.certs import plansandbox as P
import tempfile
d = tempfile.mkdtemp()
P.lockdown(d)
P.RECORDING[0] = []
r = urllib.request.Request('https://10.9.9.9/api', data=b'{"k":"STANDIN"}', method='POST',
                           headers={'X-Api-Key': 'STANDIN'})
urllib.request.urlopen(r, timeout=5).read()
f = ftplib.FTP_TLS(timeout=5); f.connect('10.9.9.8', 21); f.login('u', 'pw'); f.prot_p()
f.storbinary('STOR /x.pem', io.BytesIO(b'abc')); f.quit()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.sendto(b'\x30\x29', ('10.9.9.10', 161))
except Exception:
    pass
try:
    socket.create_connection(('10.9.9.11', 445), timeout=1)
except Exception:
    pass
print(json.dumps(P.RECORDING[0]))
""" % os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        got = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr.decode()[-500:])
        evs = json.loads(got.stdout.decode().strip().splitlines()[-1])
        kinds = [e['kind'] for e in evs]
        self.assertIn('http', kinds)
        h = [e for e in evs if e['kind'] == 'http'][0]
        self.assertEqual((h['method'], h['url'], h['own']), ('POST', 'https://10.9.9.9/api', True))
        self.assertEqual(h['headers'].get('X-api-key') or h['headers'].get('X-Api-Key'), 'STANDIN')
        cmds = [e['cmd'] for e in evs if e['kind'] == 'ftp-cmd']
        self.assertEqual(cmds[:5], ['AUTH TLS', 'USER u', 'PASS ••••', 'PBSZ 0', 'PROT P'])
        self.assertEqual([e['cmd'] for e in evs if e['kind'] == 'ftp-put'], ['STOR /x.pem'])
        socks = [e for e in evs if e['kind'] == 'socket']
        self.assertEqual([(e['how'], e['host'], e['port']) for e in socks],
                         [('udp', '10.9.9.10', 161), ('tcp', '10.9.9.11', 445)])
        self.assertEqual(socks[0]['hex'], '3029')
        from acmelib.certs import runplan as R
        steps = R.steps_of(evs)
        words = [st['words'] for st in steps]
        self.assertTrue(any('FTPS' in w for w in words), words)
        self.assertTrue(any('UDP' in w for w in words), words)
        self.assertTrue(any('445' in w for w in words), words)


class Answers(unittest.TestCase):
    """The canned answers of a module's recording: a setting's value where an answer names it,
    those of the module's version first."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def test_settings_put_in(self):
        from acmelib.certs import runplan as R
        rules = R.answers_of('cisco_fmc', {'host': 'fmc'}, {
            'enroll_devices': 'ftd-1\nftd-2', 'decryption_policy': 'Inbound',
            'decryption_policies': ''})
        devs = [r for r in rules if 'devicerecords' in r.get('url', '')][0]['body']['items']
        self.assertEqual([d['name'] for d in devs], ['ftd-1', 'ftd-2'])
        pols = [r for r in rules if 'decryptionpolicies' in r.get('url', '')][0]['body']
        self.assertEqual([p['name'] for p in pols['items']], ['Inbound'])
        cp = R.answers_of('aruba_clearpass', {'server': 'cppm01'}, {})
        self.assertIn('"cppm01"', json.dumps(cp))
        self.assertNotIn('{CFG:', json.dumps(R.answers_of('aruba_clearpass', {}, {})))
        ilo = R.answers_of('redfish', {}, {}, version='ilo')
        self.assertIn('iLO', json.dumps(ilo[:len(R.ANSWERS['redfish@ilo'])]))
        # the version's rules first, then the kind's
        self.assertEqual(ilo[len(ilo) - len(R.ANSWERS['redfish'])]['url'],
                         R.ANSWERS['redfish'][0]['url'])
        self.assertNotIn('iLO', json.dumps(R.answers_of('redfish', {}, {})))

    def test_recorded_to_the_end(self):
        """Prism Central with a cluster of the user's name: found, replaced, the task done."""
        from acmelib.certs import runplan as R
        cfg = {'host': 'pc.example.test', 'auth': 'api_key', 'api_key': 'stand-in',
               'cluster': 'prod-cluster', '_version': '7.5'}
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'nutanix', 'name': 'pc', 'op': 'deploy',
            'config': cfg, 'options': {}, 'seconds': 20,
            'answers': R.answers_of('nutanix', cfg, {}, version='7.5')}],
            'cert': {'names': ['www.example.com'], 'key_type': 'ec-256'}}, timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), run.get('error'))
        calls = [(e['method'], e['url'].split('/api/', 1)[-1]) for e in run['events']
                 if e['kind'] == 'http']
        # the task asked for while it runs, then done
        self.assertEqual([m for m, u in calls], ['GET', 'GET', 'PUT', 'GET', 'GET'])
        self.assertTrue(calls[2][1].endswith('/ssl-certificate'), calls)
        self.assertIn('/config/tasks/', calls[3][1])
        self.assertEqual([e['seconds'] for e in run['events'] if e['kind'] == 'wait'], [5.0])


class SandboxAnswers(unittest.TestCase):
    """The recording's answers (plansandbox.Answers): rules used a number of times, values the
    module sent echoed, SSH commands answered; and only the module's own sleeps are waits."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def test_times_and_sent(self):
        from acmelib.certs import plansandbox as P
        a = P.Answers([
            {'method': 'GET', 'url': r'/list$', 'times': 1, 'body': []},
            {'method': 'GET', 'url': r'/list$', 'body': [{'alias': '{SENT:alias}',
                                                          'svm': '{SENT:svm.name}'}]}])
        self.assertEqual(json.loads(a('GET', 'https://d/list')[2]), [])
        a('POST', 'https://d/import', b'{"alias": "acme-x\\"1", "svm": {"name": "vs1"}}')
        self.assertEqual(json.loads(a('GET', 'https://d/list')[2]),
                         [{'alias': 'acme-x"1', 'svm': 'vs1'}])
        self.assertEqual(json.loads(a('GET', 'https://d/list')[2])[0]['svm'], 'vs1')
        self.assertEqual(a('GET', 'https://d/other')[2], b'{}')

    def test_ssh(self):
        from acmelib.certs import plansandbox as P
        a = P.Answers([], [{'command': r'^show x', 'times': 1, 'stdout': 'first'},
                           {'command': r'^show x', 'stdout': 'then {SESSION}'},
                           {'command': '', 'input': r'import', 'exit': 1, 'stderr': 'no'}])
        self.assertEqual(a.ssh('show x'), (0, 'first', ''))
        self.assertEqual(a.ssh('show x'), (0, 'then %s' % P.SESSION, ''))
        self.assertEqual(a.ssh('', b'crypto pki import t'), (1, '', 'no'))
        self.assertIsNone(a.ssh('write memory'))

    def test_text_bodies_and_seen_with_braces(self):
        from acmelib.certs import plansandbox as P
        a = P.Answers([
            {'url': r'/xml$', 'body': '<r><alias>{SENT:alias}</alias><csr>{CSR}</csr></r>'},
            {'url': r'/jtext$', 'body': '{"csr": "{CSR}", "alias": "{SENT:alias}"}'}])
        a.csr = '-----BEGIN CERTIFICATE REQUEST-----\nAAA\n-----END CERTIFICATE REQUEST-----\n'
        a('POST', 'https://d/import', b'{"alias": "acme-1"}')
        self.assertEqual(a('GET', 'https://d/xml')[2].decode(),
                         '<r><alias>acme-1</alias><csr>%s</csr></r>' % a.csr)
        got = json.loads(a('GET', 'https://d/jtext')[2])
        self.assertEqual((got['csr'], got['alias']), (a.csr, 'acme-1'))
        # {SEEN:regex} whose regex holds braces of its own
        s = P.Answers([], [{'command': '^list', 'stdout': 'id {SEEN:import ([a-z]{3}\\d{1,2})} ok'}])
        s.ssh('import abc12 now')
        self.assertEqual(s.ssh('list'), (0, 'id abc12 ok', ''))
        self.assertEqual(P.fill_seen('x {SEEN:a{2', lambda m: 'never'), 'x {SEEN:a{2')

    def test_text_body_starting_with_a_placeholder(self):
        # round 2a: "{CSR}" alone (or "{SENT:x} ...") was taken for JSON - the PEM came back
        # with \n escapes, a value sent JSON-escaped
        from acmelib.certs import plansandbox as P
        a = P.Answers([{'method': 'GET', 'url': 'csr$', 'body': '{CSR}'},
                       {'method': 'GET', 'url': 'name$', 'body': '{SENT:alias} is the alias'}])
        a.csr = '-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n'
        a('POST', 'https://x/set', {'alias': 'a"b'})
        self.assertEqual(a('GET', 'https://x/csr')[2].decode(), a.csr)
        self.assertEqual(a('GET', 'https://x/name')[2].decode(), 'a"b is the alias')

    def test_serial_of_the_certificate_sent(self):
        # {SERIAL} (1.0.96): the serial of the last certificate sent over SSH - CUCM's
        # "show cert own" after the certificate pasted to "set cert import own"
        from acmelib.certs import plansandbox as P, pki
        key = pki.make_key('ec-256')
        one = pki.self_signed(key, ['one.example.test'], days=3)
        two = pki.self_signed(key, ['two.example.test'], days=3)
        s = P.Answers([], [{'command': '^show', 'stdout': 'SerialNumber: [ {SERIAL} ]'}])
        self.assertEqual(s.ssh('show'), (0, 'SerialNumber: [  ]', ''), 'none sent: empty')
        s.ssh('import', one.encode())
        self.assertEqual(s.ssh('show')[1], 'SerialNumber: [ %s ]' % pki.cert_info(one)['serial'])
        # the last one sent - in the same input as the command answered too
        got = s.ssh('show', ('set cert import own tomcat x\n' + two).encode())[1]
        self.assertEqual(got, 'SerialNumber: [ %s ]' % pki.cert_info(two)['serial'])

    def test_recording_on_again_after_acme_own_work_failed(self):
        from acmelib.certs import plansandbox as P, devicekey
        from acmelib.plugins import base

        class PlanDevice(base.Target):
            kind = 'plandevice_t'
            device_key = True

            def device_csr(self, req):
                return 'never asked'
        base.REGISTRY.found.setdefault('target', {})[PlanDevice.kind] = PlanDevice
        was = devicekey.dummy_csr

        def broken(*a, **k):
            raise ValueError('no CSR here')
        devicekey.dummy_csr = broken
        seen = []
        real = P._unrecorded.__exit__

        def spy(self, *exc):
            r = real(self, *exc)
            seen.append(P.RECORDING[0] is self.events)
            return r
        P._unrecorded.__exit__ = spy
        try:
            got = P.run_one({'cert': {'names': ['a.example.test']}},
                            {'family': 'target', 'kind': 'plandevice_t', 'op': 'device_csr',
                             'config': {}, 'name': 'x'}, [None])
        finally:
            devicekey.dummy_csr = was
            P._unrecorded.__exit__ = real
            base.REGISTRY.found['target'].pop(PlanDevice.kind, None)
        self.assertIn('no CSR here', got['error'])
        self.assertEqual(seen, [True])
        self.assertIsNone(P.RECORDING[0])

    def test_only_the_modules_sleeps_wait(self):
        from acmelib.certs import plansandbox as P
        ev, clock = [], P.CLOCK[0]
        P.RECORDING[0] = ev
        try:
            exec('sleep(0.001)', {'__name__': 'subprocess', 'sleep': P._sleep})
            self.assertEqual((ev, P.CLOCK[0]), ([], clock))
            exec('sleep(30)', {'__name__': 'acmelib.plugins.targets.x', 'sleep': P._sleep})
            self.assertEqual([(e['kind'], e['seconds']) for e in ev], [('wait', 30.0)])
        finally:
            P.RECORDING[0] = None
            P.CLOCK[0] = clock

    def record(self, kind, cfg, opts=None, version=''):
        from acmelib.certs import runplan as R
        cfg = dict(cfg, _version=version)
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': kind, 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts or {}, 'seconds': 30,
            'answers': R.answers_of(kind, cfg, opts, version=version),
            'ssh_answers': R.ssh_answers_of(kind, cfg, opts, version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'rsa-2048'}}, timeout=120)
        self.assertEqual(err, '')
        self.assertFalse(got['r1'].get('error'), got['r1'].get('error'))
        return got['r1']['events']

    def test_recorded_through(self):
        """IOS XE (SSH answers) binds and saves; ONTAP installs, then finds what it installed;
        a PKCS#12 made on the way is no wait."""
        evs = self.record('cisco_iosxe', {'host': 'sw1', 'user': 'acme', 'auth': 'password',
                                          'password': 'stand-in'}, version='17.12')
        cmds = [e['command'] for e in evs if e['kind'] == 'ssh-run']
        self.assertTrue(any(c.startswith('show crypto pki certificates ') for c in cmds), cmds)
        # saved; then (1.0.98: the device lists earlier trustpoints of acme's) the oldest
        # removed - after the save, the save its last command but the listing
        self.assertIn('write memory', cmds)
        self.assertTrue(all(c.startswith('show running-config') or not c.strip()
                            for c in cmds[cmds.index('write memory') + 1:]), cmds)
        self.assertFalse([e for e in evs if e['kind'] == 'wait'])
        evs = self.record('netapp_ontap', {'host': 'c1', 'user': 'u', 'password': 'p'},
                          {'svm': 'vs-prod'}, version='9.10')
        calls = [(e['method'], e['url'].split('/api/', 1)[1].split('?')[0]) for e in evs
                 if e['kind'] == 'http']
        self.assertIn(('POST', 'security/certificates'), calls)
        # bound (a job, asked for again after its 3 s), then acme's oldest one deleted
        i = calls.index(('PATCH', 'svm/svms/02c9e252-41be-11e9-81d5-00a0986138f7/web'))
        self.assertEqual([m for m, u in calls[i + 1:]], ['GET', 'GET', 'GET', 'DELETE'])
        self.assertEqual([e['seconds'] for e in evs if e['kind'] == 'wait'], [3.0])



class RenewalPaths(unittest.TestCase):
    """What happens takes the real renewal path of each module: the certificate acme put there
    before found, replaced, the old one cleaned up - every call answered as the device does
    (no stand-in answer), the decisions said (group: hpe_synergy .. redfish_idrac)."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def record(self, kind, cfg, opts=None, version='', later=False):
        from acmelib.certs import runplan as R
        cfg = dict(cfg, _version=version)
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': kind, 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts or {}, 'seconds': 30,
            'answers': R.answers_of(kind, cfg, opts, later=later, version=version),
            'ssh_answers': R.ssh_answers_of(kind, cfg, opts, version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'rsa-2048'}}, timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), '%s: %s' % (kind, run.get('error')))
        evs = run['events']
        self.assertFalse([e for e in evs if e.get('fallback')],
                         '%s: a call no answer of the module matched' % kind)
        return evs

    @staticmethod
    def seen(evs):
        """Each call and step as one line: "GET url", "SSH command", "SAY words"."""
        out = []
        for e in evs:
            if e['kind'] == 'http':
                out.append('%s %s' % (e['method'], e['url']))
            elif e['kind'] == 'ssh-run':
                out.append('SSH %s' % e['command'])
            elif e['kind'] == 'say':
                out.append('SAY %s' % e['words'])
        return out

    def in_order(self, evs, *wants):
        lines, i = self.seen(evs), 0
        for w in wants:
            while i < len(lines) and w not in lines[i]:
                i += 1
            self.assertLess(i, len(lines), '%r not found in order in %s' % (w, lines))

    def test_device_lists_kept_and_old_deleted(self):
        pw = {'host': 'dev.example.test', 'user': 'acme', 'password': 'stand-in'}
        evs = self.record('kemp', {'host': 'lm', 'apikey': 'k'},
                          {'virtual_services': '192.0.2.10:443'})
        self.in_order(evs, 'POST https://lm/accessv2', 'SAY added acme-',
                      'SAY the intermediate acme-ca-', 'SAY 192.0.2.10:443 uses',
                      'SAY deleted the old acme-')
        evs = self.record('mikrotik', dict(pw), {'services': 'www-ssl'})
        self.in_order(evs, 'GET https://dev.example.test/rest/certificate',
                      'POST https://dev.example.test/rest/certificate/import',
                      'DELETE https://dev.example.test/rest/file/', 'SAY imported as acme-',
                      'PATCH https://dev.example.test/rest/ip/service/',
                      'DELETE https://dev.example.test/rest/certificate/')
        evs = self.record('mikrotik', dict(pw, mode='ssh'), {'services': 'www-ssl'})
        self.in_order(evs, 'SSH :foreach c in=[/certificate find', 'SSH /certificate import',
                      'SSH /ip service set', 'SSH /certificate remove')
        evs = self.record('nginx_proxy_manager', {'url': 'http://npm:81', 'user': 'a@b',
                                                  'password': 'p'}, {})
        self.in_order(evs, 'POST http://npm:81/api/nginx/certificates',
                      'PUT http://npm:81/api/nginx/proxy-hosts/3',
                      'DELETE http://npm:81/api/nginx/certificates/4')
        evs = self.record('nsx', dict(pw), {'virtual_server': 'vs1'})
        self.in_order(evs, 'GET https://dev.example.test/policy/api/v1/infra/certificates/acme-',
                      'PUT https://dev.example.test/policy/api/v1/infra/lb-virtual-servers/vs1',
                      'DELETE https://dev.example.test/policy/api/v1/infra/certificates/acme-')
        evs = self.record('juniper_srx', dict(pw), {'ike_policies': 'ike1'})
        self.in_order(evs, 'GET https://dev.example.test:3443/rpc/get-pki-local-certificate',
                      'SAY loaded the local certificate acme-',
                      'SAY delete security ike policy ike1 certificate local-certificate acme-',
                      'SAY removed the older acme-')
        evs = self.record('nginx_unit', dict(pw, auth='password'), {})
        self.in_order(evs, 'http://localhost/certificates', 'SAY uploaded the bundle',
                      'SAY listener *:443 uses', 'SAY deleted the old bundle')

    def test_decisions_said(self):
        evs = self.record('ispconfig', {'host': 'panel', 'user': 'r', 'password': 'p'},
                          {'website': 'shop.example.com'})
        self.in_order(evs, 'sites_web_domain_get',
                      'SAY shop.example.com has another certificate - replacing it',
                      'sites_web_domain_update', 'POST https://panel:8080/remote/json.php?logout')
        evs = self.record('proxmox', {'host': 'pve', 'token_id': 'a@pve!t', 'token_secret': 's'},
                          {})
        self.in_order(evs, 'GET https://pve:8006/api2/json/nodes',
                      'SAY pve1 serves another certificate - replacing it',
                      'SAY pve2 serves another certificate - replacing it')
        evs = self.record('qnap', {'host': 'nas', 'user': 'admin', 'password': 'p'}, {})
        self.in_order(evs, 'SAY /etc/stunnel/stunnel.pem holds another certificate',
                      'SSH sh -c \'/etc/init.d/stunnel.sh restart\'', 'SAY stunnel restarted')
        evs = self.record('pure_flasharray', {'host': 'fa', 'api_token': 't'}, {})
        self.in_order(evs, 'GET https://fa/api/2.36/certificates?names=management',
                      'SAY management holds another certificate - replacing it',
                      'PATCH https://fa/api/2.36/certificates?names=management')
        evs = self.record('redfish', {'host': 'bmc', 'user': 'u', 'password': 'p'},
                          {'reset': True})
        # what it serves is read (1.0.98: an earlier certificate, served_der) - replaced
        self.in_order(evs, 'SAY bmc serves another certificate - this one is put there',
                      'GET https://bmc/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates',
                      'POST https://bmc/redfish/v1/CertificateService/Actions/'
                      'CertificateService.ReplaceCertificate', 'Manager.Reset')
        evs = self.record('paloalto', {'host': 'pa', 'auth': 'password', 'user': 'admin',
                                       'password': 'p'}, {'keep': 1})
        self.in_order(evs, 'SAY imported acme-', 'SAY the intermediate acme-ca-',
                      'SAY deleted the old acme-', 'SAY commit job 1234 started',
                      'SAY committed (job 1234)')

    def test_first_and_later(self):
        k8s = {'host': 'https://k8s:6443', 'token': 't'}
        first = self.seen(self.record('kubernetes', k8s, {'secret': 'web-tls'}))
        later = self.seen(self.record('kubernetes', k8s, {'secret': 'web-tls'}, later=True))
        self.assertIn('SAY made default/web-tls', first)
        self.assertIn('SAY updated default/web-tls', later)
        ns = {'host': 'ns', 'user': 'acme', 'password': 'p'}
        opts = {'certkey': 'www', 'vservers': 'vs1'}
        first = self.seen(self.record('netscaler', ns, opts))
        later = self.seen(self.record('netscaler', ns, opts, later=True))
        self.assertIn('SAY www is not there yet - added', first)
        self.assertIn('SAY bound www to vs1', first)
        self.assertTrue([x for x in later if x.startswith('SAY www is there (on acme-')], later)
        self.assertIn('SAY www is bound to vs1 already', later)
        self.assertTrue([x for x in later if x.startswith('SAY www is linked to acme-ca-')])

    def test_sent_fingerprint_and_names(self):
        """Answers told apart by the body sent (one address, the command in the body); {FP} the
        fingerprint of the certificate deployed; a module's own names (plan_name)."""
        from acmelib.certs import plansandbox as P
        a = P.Answers([{'url': r'/api$', 'sent': r'"cmd": "list"', 'body': {'n': 1}},
                       {'url': r'/api$', 'sent': r'type=op', 'body': '<ok/>'},
                       {'url': r'/api$', 'body': {'n': 0}}])
        self.assertEqual(json.loads(a('POST', 'https://d/api', b'{"cmd": "list"}')[2]), {'n': 1})
        self.assertEqual(a('POST', 'https://d/api', b'type=op&cmd=x')[2], b'<ok/>')
        self.assertEqual(json.loads(a('POST', 'https://d/api', {'cmd': 'add'})[2]), {'n': 0})
        from acmelib.certs import pki
        from acmelib.plugins.targets import _common as C, juniper_srx as J
        key = pki.make_key('ec-256')

        class B(object):
            cert_pem = pki.self_signed(key, ['fp.example.test'], days=3)
            names = ['fp.example.test']
            name = 'fp.example.test'
            not_before = 1760000000
            serial = '0a1b2c3d4e5f'
        a.bundle, a.options = B(), {}
        self.assertEqual(a.earlier('{FP}'), C.fp_of(B()))
        a.namer = J.JuniperSrxTarget.plan_name
        self.assertEqual(a.earlier('{CURRENT}'), J.srx_id(B(), {}))
        self.assertTrue(C.ours(a.earlier('{EARLIER}'), J.srx_prefix(B(), {})))
        self.assertNotEqual(a.earlier('{EARLIER}'), J.srx_id(B(), {}))


class OwnVersionAnswers(unittest.TestCase):
    """A version of your own made from a shipped one (Download a start), or an override, gets
    the canned answers of the shipped version it speaks like (1.0.98: dell_ome@3.0's answers
    were not given to a version made from 3.0 - its What happens ended in an error)."""

    def test_answer_version(self):
        from acmelib.plugins import base as B
        from acmelib.certs import runplan as RP
        B.REGISTRY.reload()
        shipped = B.REGISTRY.versions['target']['dell_ome']['3.0']
        own = type(shipped.__name__, (shipped,), {'module_version': 'own_x', '_origin': 'custom',
                                                  '_replaced': None, '__module__': 'acme_local_plugins.t'})
        with unittest.mock.patch.dict(B.REGISTRY.versions['target']['dell_ome'], {'own_x': own}):
            self.assertEqual(RP._answer_ver(own), '3.0')
        over = type(shipped.__name__, (shipped,), {'module_version': '3.0', '_origin': 'custom',
                                                   '_replaced': shipped, '__module__': 'acme_local_plugins.t'})
        self.assertEqual(RP._answer_ver(over), '3.0')
        self.assertEqual(RP._answer_ver(shipped), '3.0')
        self.assertEqual(RP._answer_ver(None), '')


class DebugDetails(unittest.TestCase):
    """1.0.98: in debug mode every request shows as it is sent - every header, the ones the
    transport adds too, the body (JSON, form fields, multipart parts, binary as size and
    sha256, a PEM as a placeholder) - and the stand-in's answer; secrets masked the same way
    everywhere; a call no prepared answer matched is marked."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def test_masking_everywhere(self):
        from acmelib.certs import plansandbox as P
        self.assertEqual(P.header_shown('Authorization', 'Basic YWRtaW46c2VjcmV0'), 'Basic ••••')
        self.assertEqual(P.header_shown('Authorization', 'Bearer abc.def'), 'Bearer ••••')
        self.assertEqual(P.header_shown('Cookie', 'sid=abc; csrf=def'), 'sid=••••; csrf=••••')
        self.assertEqual(P.header_shown('X-Auth-Token', 'zz'), '••••')
        self.assertEqual(P.header_shown('X-Api-Key', 'zz'), '••••')
        self.assertEqual(P.header_shown('Content-Type', 'application/json'), 'application/json')
        u = P.mask_url('https://u:pw@h/api?client_secret=a&p12Password=b&sid=c&key=d&page=2', {})
        for v in ('pw', '=a', '=b', '=c', '=d'):
            self.assertNotIn(v, u)
        self.assertIn('page=2', u)
        j = P.mask_json({'password': 'x1', 'p12Password': 'x2', 'client_secret': 'x3',
                         'passphrase': 'x4', 'token': 'x5', 'key': 'x6', 'privateKey': 'x7',
                         'keyType': 'RSA', 'name': 'n', 'nested': {'secret': 'x8'},
                         'SI': 'STANDIN-1'}, {'STANDIN-1': 'the password'})
        for k in ('password', 'p12Password', 'client_secret', 'passphrase', 'token', 'key',
                  'privateKey'):
            self.assertEqual(j[k], '••••', k)
        self.assertEqual((j['keyType'], j['name'], j['nested']['secret']), ('RSA', 'n', '••••'))
        self.assertEqual(j['SI'], '•••• (the password)')
        # form fields, PEM, command lines
        shown, facts = P.mask_body(b'user=a&password=b&x=1', {})
        self.assertEqual((shown, facts['format']), ({'user': 'a', 'password': '••••', 'x': '1'},
                                                    'form'))
        key = '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'
        cert = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'
        t = P.mask_text(key + '\n' + cert, {})
        self.assertNotIn('MIIE', t)
        self.assertIn('private key', t)
        self.assertIn('‹certificate, PEM', t)
        for cmd, gone in ((("sshpass -p 'Sec1' ssh h"), 'Sec1'),
                          ('openssl pkcs12 -export -passout pass:Sec2 -in a', 'Sec2'),
                          ("Import-PfxCertificate -Password (ConvertTo-SecureString 'Sec3' "
                           "-AsPlainText -Force)", 'Sec3'),
                          ('keytool -importkeystore -storepass Sec4 -x', 'Sec4'),
                          ("Set-Thing -Password 'Sec5'", 'Sec5'),
                          ('PFX_PASSWORD=Sec6 ./import', 'Sec6'),
                          ('x --password="Sec7" y', 'Sec7')):
            self.assertNotIn(gone, P.mask_command(cmd, {}), cmd)
        self.assertEqual(P.mask_command('ssh -p 22 host', {}), 'ssh -p 22 host')
        self.assertEqual(P.mask_command('$c = Get-Credential -Password $pw', {}),
                         '$c = Get-Credential -Password $pw')

    def test_multipart_and_binary(self):
        from acmelib.certs import plansandbox as P
        from acmelib.plugins.targets import _common as C
        body, ctype = C.multipart([('password', 'Pfx-Secret-9'),
                                   ('file', ('www.pfx', b'\x30\x82\x05\x00\xff\xfe', 'application/x-pkcs12')),
                                   ('cert', ('www.pem', b'-----BEGIN CERTIFICATE-----\nMIIB\n'
                                             b'-----END CERTIFICATE-----\n', 'text/plain'))])
        shown, facts = P.mask_body(body, {}, ctype)
        self.assertEqual(facts['format'], 'multipart')
        self.assertEqual([(p['name'], p['filename'], p['type'], p['size']) for p in facts['parts']],
                         [('password', None, None, 12), ('file', 'www.pfx', 'application/x-pkcs12', 6),
                          ('cert', 'www.pem', 'text/plain', 59)])
        self.assertNotIn('Pfx-Secret-9', shown)
        self.assertIn('file "www.pfx"', shown)
        self.assertIn('sha256', shown)
        self.assertIn('‹certificate, PEM', shown)
        shown, facts = P.mask_body(b'\x00\xff\x10binary', {})
        self.assertEqual(facts['format'], 'binary')
        self.assertIn(facts['sha256'][:16], shown)

    def record_in(self, code):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        lst = Listener()
        full = ('import json, os, sys\nsys.path.insert(0, %r)\nfrom acmelib.certs import '
                'plansandbox as P\nimport tempfile\nP.lockdown(tempfile.mkdtemp())\nPORT = %d\n'
                % (root, lst.port)) + code
        got = subprocess.run([sys.executable, '-I', '-c', full], capture_output=True, timeout=60)
        lst.stop = True
        self.assertEqual(got.returncode, 0, got.stderr.decode()[-800:])
        self.assertEqual(lst.seen, 0, 'something reached the network')
        return json.loads(got.stdout.decode().strip().splitlines()[-1])

    def test_request_as_sent_and_its_answer(self):
        evs = self.record_in(r"""
P.RECORDING[0] = ev = []
a = P.Answers([{'method': 'GET', 'url': '/known$', 'status': 404,
                'headers': {'Content-Type': 'application/json', 'X-Request-Id': 'r1'},
                'body': {'message': 'Certificate does not exist'}}],
              [{'command': '^show', 'stdout': 'shown'}])
ctx = P.PlanContext({}, 'target:t', a)
ctx.http('POST', 'https://dev.example.test/api/login?api_key=STANDIN', body=b'user=u&password=STANDIN',
         headers={'Authorization': 'Basic dTpw', 'Cookie': 'sid=1', 'Content-Type':
                  'application/x-www-form-urlencoded', 'X-Auth-Token': 'tok'})
ctx.http('GET', 'https://dev.example.test/known')
ctx.http('PUT', 'https://dev.example.test/x', body={'p12Password': 'pw', 'name': 'n'})
s = ctx.ssh({'host': 'h', 'user': 'u', 'password': 'p'})
s.run('show x')
s.run("sudo -S -p '' sh -c 'cat > /x'", input=b'STANDIN\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n')
s.put(b'-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n', '/etc/k.pem', 0o600, 'root:root')
P.RECORDING[0] = None
print(json.dumps([P.clean(e, {'STANDIN': 'the password'}) for e in ev]))
""")
        text = json.dumps(evs)
        for gone in ('STANDIN', 'dTpw', '"tok"', 'sid=1', 'MIIE', '"pw"'):
            self.assertNotIn(gone, text)
        login, known, put = [e for e in evs if e['kind'] == 'http']
        names = [h[0] for h in login['wire']['headers']]
        for h in ('Host', 'Content-Length', 'User-Agent', 'Accept-Encoding', 'Connection',
                  'Content-Type', 'Authorization', 'Cookie', 'X-Auth-Token'):
            self.assertIn(h, names)
        hv = {h[0]: h[1] for h in login['wire']['headers']}
        self.assertEqual(hv['Authorization'], 'Basic ••••')
        self.assertEqual(hv['Content-Length'], str(len(b'user=u&password=STANDIN')))
        self.assertTrue(login['wire']['line'].startswith('POST /api/login?api_key=••••'))
        self.assertEqual(login['wire']['body'], 'user=u&password=•••• (the password)')
        self.assertEqual(login['body_facts']['format'], 'form')
        # a sign-in no rule answered: a stand-in session, marked
        self.assertEqual(login['fallback'], 'sign-in')
        self.assertNotIn('fallback', known)
        self.assertEqual(known['answered']['status'], 404)
        self.assertEqual(known['answered']['body'], {'message': 'Certificate does not exist'})
        self.assertIn(['X-Request-Id', 'r1'], known['answered']['headers'])
        self.assertEqual(put['fallback'], 'empty')
        self.assertEqual(put['body']['p12Password'], '••••')
        runs = [e for e in evs if e['kind'] == 'ssh-run']
        self.assertEqual(runs[0]['answer']['stdout'], 'shown')
        self.assertNotIn('fallback', runs[0])
        self.assertEqual(runs[1]['fallback'], 'empty')
        self.assertTrue(runs[1]['input']['body'].startswith('•••• (the sudo password)'))
        self.assertIn('‹certificate, PEM', runs[1]['input']['body'])
        putev = [e for e in evs if e['kind'] == 'ssh-put'][0]
        self.assertIn("chmod 600", putev['command'])
        self.assertIn('chown root:root', putev['command'])
        # the steps carry it all to the page
        from acmelib.certs import runplan as R
        steps = R.steps_of(evs)
        http = [s for s in steps if (s.get('detail') or {}).get('url')]
        self.assertEqual(http[0]['detail']['answer']['fallback'], 'sign-in')
        self.assertEqual(http[1]['detail']['answer']['status'], 404)
        self.assertTrue(http[0]['detail']['wire']['headers'])
        cmds = [s for s in steps if (s.get('detail') or {}).get('command') and
                s['kind'] in ('command', 'delete')]
        self.assertEqual(cmds[1]['detail']['answer']['fallback'], 'empty')
        self.assertIn('input_body', cmds[1]['detail'])

    def test_secret_names_and_look_alikes(self):
        """1.0.98: what a name says about a secret is no secret (ISPConfig's "code": "ok",
        Nutanix's privateKeyAlgorithm were masked)."""
        from acmelib.certs import plansandbox as P
        secrets = ['password', 'p12Password', 'client_secret', 'passphrase', 'token',
                   'access_token', 'refresh_token', 'apiKey', 'api_key', 'key', 'privateKey',
                   'private_key', 'privkey', 'keyPem', 'sid', 'sessionid', 'sessionId',
                   'authToken', 'secret', 'pin', 'BoxCertPassword', 'inPassword', 'passwd',
                   'signature', 'cookie', 'credentials', 'pfxPassword', 'keystore_password']
        alike = ['code', 'privateKeyAlgorithm', 'keyType', 'publicKey', 'public_key', 'keySize',
                 'keyUsage', 'key_length', 'signatureAlgorithm', 'tokenType', 'tokenExpires',
                 'sessionTimeout', 'passwordPolicy', 'hasPassword', 'enable_syno_token',
                 'isPrivate', 'authType', 'author', 'certificateAuthority', 'pinned',
                 'keyAlgorithm', 'token_type', 'password_expires', 'privateKeyFormat']
        secrets += ['auth', 'authorization', 'Authorization', 'auth_token', 'authkey']
        alike += ['issuingCertificateAuthorityId', 'authority', 'certificateAuthorityName',
                  'key-name', 'key_name', 'session_cookie_name', 'cookieName']
        # names of things and public keys shown; private keys and secret values never
        got = P.mask_json({'key-name': 'acme-www.key', 'session_cookie_name': 'JSESSIONID',
                           'error': {'code': 'InvalidParameter', 'message': 'm'},
                           'acme_key': 'acme-push-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA acme@n1',
                           'ssh_key': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA u@h',
                           'key': '-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----',
                           'private_key': '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----',
                           'api_key': 'ssh-ed25519-not-really'}, {})
        self.assertEqual((got['key-name'], got['session_cookie_name'], got['error']['code']),
                         ('acme-www.key', 'JSESSIONID', 'InvalidParameter'))
        self.assertTrue(got['acme_key'].startswith('acme-push-ed25519 '))
        self.assertTrue(got['ssh_key'].startswith('ssh-ed25519 '))
        self.assertIn('public key', got['key'])
        self.assertNotIn('MIIE', got['private_key'])
        self.assertEqual(got['api_key'], '••••')
        self.assertEqual([n for n in secrets if not P.secret_name(n)], [])
        self.assertEqual(P.mask_url('https://p/v1/x?issuingCertificateAuthorityId=ca1&auth=s', {}),
                         'https://p/v1/x?issuingCertificateAuthorityId=ca1&auth=••••')
        self.assertEqual([n for n in alike if P.secret_name(n)], [])
        got = P.mask_json({'code': 'ok', 'privateKeyAlgorithm': 'RSA_2048', 'password': 'x'}, {})
        self.assertEqual(got, {'code': 'ok', 'privateKeyAlgorithm': 'RSA_2048', 'password': '••••'})

    def test_earlier_n(self):
        import time as _t
        from acmelib.certs import plansandbox as P

        class B(object):
            name, names, not_before, serial = 'www', ['www.example.com'], _t.time(), 'ab' * 8
        a = P.Answers([])
        a.bundle, a.options = B(), {}
        got = a.earlier('{CURRENT} {EARLIER} {EARLIER2} {EARLIER3} {EARLIER4}').split()
        self.assertEqual(len(set(got)), 5, got)
        self.assertEqual(a.earlier('{EARLIER1}'), a.earlier('{EARLIER}'))
        self.assertTrue(got[3] < got[2] < got[1], got)          # older dates, older names

    def test_served_earlier_then_new(self):
        """What the device serves: an earlier certificate of the same names before the new
        one was sent (the renewal's way taken), the new one after (a check after it passes)."""
        got = self.record_in(r"""
P._patch_modules({})
from acmelib.plugins.targets import _common as C
P.RECORDING[0] = ev = []
a = P.Answers([])
P.ANSWERS[0] = a
a.bundle = P.dummy_bundle({'names': ['www.example.com'], 'key_type': 'ec-256'})
ctx = P.PlanContext({}, 'target:t', a)
want = C.fp_of(a.bundle)
before = C.served_fingerprint('dev.example.test', 443)
ctx.http('POST', 'https://dev.example.test/login', body={'user': 'u', 'password': 'p'})
signed_in = C.served_fingerprint('dev.example.test', 443)
ctx.http('POST', 'https://dev.example.test/upload', body={'cert': a.bundle.cert_pem})
after = C.served_fingerprint('dev.example.test', 443)
from acmelib.certs import pki
earlier = pki.cert_info(a.earlier_pem())
P.RECORDING[0] = None
print(json.dumps({'before': before == want, 'signed_in': signed_in == want, 'after': after == want,
                  'same_earlier': before == C.served_fingerprint.__globals__['hashlib'].sha256(
                      C.pem_to_der(a.earlier_pem())).hexdigest(),
                  'names': earlier.get('names') or earlier.get('sans'),
                  'served': [e.get('served') for e in ev if e['kind'] == 'check']}))
""")
        self.assertEqual((got['before'], got['signed_in'], got['after'], got['same_earlier']),
                         (False, False, True, True))
        self.assertEqual(got['served'], ['earlier', 'earlier', 'new'])
        self.assertIn('www.example.com', json.dumps(got['names']))

    def test_paths_and_placeholders_shown(self):
        """A key's path is no key (F5's certKeyChain "key": "/Common/x.key"), a real key or a
        key-looking value stays dots; a stand-in ‹placeholder› percent-encoded in a URL reads
        as itself (1.0.98)."""
        from acmelib.certs import plansandbox as P
        got = P.mask_json({'key': '/Common/acme-www.key', 'privateKey': 'C:\\c\\a.key',
                           'keyFile': 'www.key', 'password': '/looks',
                           'apiKey': '/x', 'k2': {'key': 'Zm9vYmFy' * 10},
                           'k3': {'key': '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'}}, {})
        self.assertEqual((got['key'], got['privateKey'], got['keyFile']),
                         ('/Common/acme-www.key', 'C:\\c\\a.key', 'www.key'))
        self.assertEqual((got['password'], got['apiKey'], got['k2']['key']), ('••••',) * 3)
        got = P.mask_json({'session': 'S3ss10n', 'enable_syno_token': 'yes', 'passwd': 'true',
                           'token_file': '/etc/acme/tok', 'password': '/abc'}, {})
        self.assertEqual(got, {'session': '••••', 'enable_syno_token': 'yes', 'passwd': 'true',
                               'token_file': '/etc/acme/tok', 'password': '••••'})
        self.assertNotIn('MIIE', json.dumps(got))
        u = P.mask_url('https://x/zones/%E2%80%B9zone%20id%E2%80%BA/c?n=%E2%80%B9a+b%E2%80%BA'
                       '&password=1', {})
        self.assertEqual(u, 'https://x/zones/‹zone id›/c?n=‹a b›&password=••••')

    def test_later_run_finds_what_the_first_kept(self):
        """What a deployment kept (ctx.kv_set) is there at the renewal - as kept for an
        earlier certificate (its fingerprint another), so the renewal's clean-up shows."""
        from acmelib.certs import plansandbox as P
        from acmelib.plugins.targets import _common as C
        b = P.dummy_bundle({'names': ['www.example.com'], 'key_type': 'ec-256'})
        fp = C.fp_of(b)
        kv = {'cert:www': {'fp': fp, 'short': fp[:16], 'thumb': C.sha1_thumb(b), 'id': 'x1'}}
        got = P.kv_as_earlier(kv, b)['cert:www']
        self.assertEqual(got['id'], 'x1')
        self.assertNotEqual(got['fp'], fp)
        self.assertEqual(len(got['fp']), 64)
        self.assertEqual(got['short'], got['fp'][:16])
        self.assertNotEqual(got['thumb'], C.sha1_thumb(b))
        self.assertTrue(got['thumb'].isupper())

    def test_modules_words_are_steps(self):
        """The module's own words (ctx.step) are steps of their own, in order, debug or not -
        between handshakes too, and a later run's own words told apart (1.0.98: dropped)."""
        from acmelib.certs import runplan as R
        evs = [{'kind': 'say', 'words': 'signed in', 'level': 'info'},
               {'kind': 'check', 'host': 'h', 'port': 443, 'served': 'earlier'},
               {'kind': 'say', 'words': 'h serves another certificate - replacing it',
                'level': 'warn'},
               {'kind': 'http', 'method': 'POST', 'url': 'https://h/upload', 'headers': {}},
               {'kind': 'check', 'host': 'h', 'port': 443, 'served': 'new'},
               {'kind': 'say', 'words': 'h serves the new certificate', 'level': 'ok'}]
        steps = R.steps_of(evs)
        said = [(s['words'], s.get('level')) for s in steps if s.get('said')]
        self.assertEqual(said, [('signed in', None),
                                ('h serves another certificate - replacing it', 'warn'),
                                ('h serves the new certificate', 'ok')])
        kinds = [s['kind'] for s in steps]
        self.assertEqual(kinds, ['info', 'check', 'info', 'call', 'check', 'info'])
        self.assertFalse(any(s.get('debug') for s in steps if s.get('said')))
        later = evs[:2] + [{'kind': 'say', 'words': 'h serves it already', 'level': 'ok'}]
        steps = R.steps_of(evs, later=later)
        self.assertIn(('h serves it already', 'Only at later renewals - when it is there already'),
                      [(s['words'], s.get('branch')) for s in steps if s.get('said')])

    def test_calls_around_ctx_are_errors(self):
        """A module that goes around ctx (urllib / http.client, a socket, a program, a DNS
        lookup) is caught: recorded as an error step, never reaching the network."""
        evs = self.record_in(r"""
import socket, subprocess, urllib.request
P.RECORDING[0] = ev = []
P.ANSWERS[0] = P.Answers([{'url': '/v1/x$', 'body': {'ok': 1}}])
def tryit(fn):
    try:
        return fn()
    except Exception as e:
        return type(e).__name__
got = tryit(lambda: urllib.request.urlopen('http://127.0.0.1:%d/v1/x' % PORT, timeout=2).read())
tryit(lambda: socket.create_connection(('127.0.0.1', PORT), 2))
tryit(lambda: subprocess.run(['curl', 'http://127.0.0.1:%d/' % PORT]))
tryit(lambda: os.system('curl http://127.0.0.1:%d/' % PORT))
tryit(lambda: socket.getaddrinfo('example.com', 443))
P.RECORDING[0] = None
P.ANSWERS[0] = None
print(json.dumps({'got': got.decode() if isinstance(got, bytes) else got, 'ev': [P.clean(e, {}) for e in ev]}))
""")
        ev = evs['ev']
        self.assertEqual(json.loads(evs['got']), {'ok': 1}, 'answered as ctx.http would be')
        by = [(e['how'], e['what'].split(' ')[0]) for e in ev if e['kind'] == 'bypass']
        self.assertEqual([b[0] for b in by], ['http.client', 'socket', 'program', 'program', 'dns'])
        from acmelib.certs import runplan as R
        steps = R.steps_of(ev)
        errs = [s for s in steps if s.get('error')]
        self.assertEqual(len(errs), 5)
        self.assertTrue(all(s['words'].startswith('The module went around acme') for s in errs))

    def test_own_http_connection_is_a_bypass(self):
        """http.client's putrequest/endheaders of a module's own (1.0.101): refused at connect,
        and written down as going around acme too (it was refused unmarked)."""
        evs = self.record_in(r"""
import http.client
P.RECORDING[0] = ev = []
def tryit(fn):
    try:
        return fn()
    except Exception as e:
        return type(e).__name__
def own():
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=2)
    c.putrequest('GET', '/x')
    c.endheaders()
got = tryit(own)
P.RECORDING[0] = None
print(json.dumps({'got': got, 'ev': [P.clean(e, {}) for e in ev]}))
""")
        self.assertNotEqual(evs['got'], None)
        by = [(e['how'], e['what']) for e in evs['ev'] if e['kind'] == 'bypass']
        self.assertEqual(len(by), 1, evs)
        self.assertEqual(by[0][0], 'http.client')
        self.assertIn('127.0.0.1', by[0][1])

    def test_json_secrets_are_stand_ins(self):
        """A secret that is JSON (1.0.101): every string in it a stand-in but for where and
        who - a password kept as a JSON list, pwd/apiToken/accessKey members reached the
        module as they were, and the scrub knew only the compact text."""
        from acmelib.certs import runplan as R
        cfg = {'password': '["Hunter2-real"]',
               'creds': '{"user":"svc","pwd":"RealPwd-777","apiToken":"AT-real-999",'
                        '"accessKey":"AK-real-1","server_url":"https://h.example.com"}'}
        sec = R.Secrets()
        out, marks = sec.stand_ins([{'key': 'password', 'type': 'secret'},
                                    {'key': 'creds', 'type': 'secret'}], cfg)
        handed = json.dumps(out)
        for real in ('Hunter2-real', 'RealPwd-777', 'AT-real-999', 'AK-real-1'):
            self.assertNotIn(real, handed)
            self.assertIn(real, sec.real)
        got = json.loads(out['creds'])
        self.assertEqual((got['user'], got['server_url']), ('svc', 'https://h.example.com'))
        self.assertEqual(len(json.loads(out['password'])), 1)
        spaced = json.dumps(json.loads(cfg['creds']))
        self.assertNotIn('RealPwd-777', json.dumps(R.scrub({'t': 'said: ' + spaced}, sec.real)))


class RenewalPathsG2(unittest.TestCase):
    """The renewal path of the targets cisco_wlc9800 .. hpe_oneview (1.0.98): the earlier
    certificate found, replaced, the older ones cleaned up, the decisions said - every call
    answered as the device does (no stand-in answer); SSH_FIRST / SSH_LATER."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def record(self, kind, cfg, opts=None, version='', later=False):
        from acmelib.certs import runplan as R
        cfg = dict(cfg, _version=version)
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': kind, 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts or {}, 'seconds': 30,
            'answers': R.answers_of(kind, cfg, opts, first=not later, later=later,
                                    version=version),
            'ssh_answers': R.ssh_answers_of(kind, cfg, opts, first=not later, later=later,
                                            version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'rsa-2048'}}, timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), '%s: %s' % (kind, run.get('error')))
        evs = run['events']
        self.assertFalse([e for e in evs if e.get('fallback')],
                         '%s: a call no answer of the module matched' % kind)
        return RenewalPaths.seen(evs)

    def in_order(self, lines, *wants):
        i = 0
        for w in wants:
            while i < len(lines) and w not in lines[i]:
                i += 1
            self.assertLess(i, len(lines), '%r not found in order in %s' % (w, lines))
            i += 1

    def test_ssh_devices(self):
        ssh = {'host': 'dev', 'user': 'acme', 'auth': 'password', 'password': 'p'}
        for ver, said in (('', 'IOS XE 17.12.4'), ('17.3', 'IOS XE 17.9.5'),
                          ('17.12', 'IOS XE 17.15.3')):
            got = self.record('cisco_wlc9800', ssh, {}, version=ver)
            self.in_order(got, 'SSH show version', 'SAY %s; trustpoints: TP-self-signed' % said,
                          'SAY imported into the new trustpoint acme-',
                          'SAY the HTTPS server uses acme-', 'SAY write memory - [OK]',
                          'SAY removed the older trustpoint acme-www.example.com-')
        got = self.record('cockpit', ssh, {})
        self.in_order(got, 'SAY /etc/cockpit/ws-certs.d holds 0-self-signed.cert',
                      'SAY Cockpit takes 90-acme-', 'SAY cockpit.service restarted',
                      'SAY deleted the old 90-acme-www.example.com-')
        got = self.record('docker_swarm', ssh, {'services': 'web_proxy'})
        self.assertTrue([x for x in got if '--secret-rm acme-www.example.com-' in x and
                         'uid=0,gid=0,mode=0444' in x], got)
        self.in_order(got, 'SAY service web_proxy rolled onto acme-',
                      'SAY removed the old secret acme-www.example.com-')
        got = self.record('esxi', ssh, {})
        self.in_order(got, 'SAY /etc/vmware/ssl/rui.crt: SHA-256 there 3f1d0c5e',
                      'SAY the files replaced kept as', 'SAY ran /etc/init.d/hostd restart',
                      'SAY saved to the boot bank')
        got = self.record('haproxy', ssh, {'cert_path': '/etc/haproxy/certs/www.pem'})
        self.in_order(got, 'SAY HAProxy has loaded /etc/haproxy/certs/www.pem',
                      'SAY HAProxy serves it now (set ssl cert, commit)')
        got = self.record('hestiacp', ssh, {'hestia_user': 'admin',
                                            'web_domains': 'example.com'})
        self.in_order(got, "SAY example.com: SSL on, Hestia's Let's Encrypt off",
                      'v-change-web-domain-sslcert admin example.com /tmp/tmp.',
                      'SAY example.com: certificate installed')
        got = self.record('horizon_cs', ssh, {})
        self.in_order(got, 'SAY imported into LocalMachine', 'SAY vdm taken off',
                      'SAY the friendly name vdm is on', 'SAY restarted VMware Horizon')

    def test_cucm_first_and_later(self):
        from acmelib.certs import runplan as R
        self.assertIn('cucm', R.SSH_LATER)
        # (a key made by the device: the bundle without a key - the sandbox's own has one, so
        # what is asked of the CLI is looked at through the answers here)
        a = R.ssh_answers_of('cucm', later=True)
        self.assertIn('tomcat-trust/{CACN_}.pem', a[0]['stdout'])
        from acmelib.certs import plansandbox as P
        from acmelib.certs import pki
        key = pki.make_key('ec-256')

        class B(object):
            cert_pem = pki.self_signed(key, ['www.example.com'], days=3)
            chain_pems = [pki.self_signed(pki.make_key('ec-256'), ['issuing-ca1.example'],
                                          days=3)]
            names = ['www.example.com']
        ans = P.Answers([], a)
        ans.bundle = B()
        out = ans.ssh('', 'show cert list trust\nexit\n')[1]
        self.assertIn('tomcat-trust/issuing-ca1.example.pem: Trust Certificate', out)
        self.assertNotIn('rrr', out)
        self.assertEqual(out.count('-trust/issuing-ca1.example.pem'), 2)  # no 2nd CA: no line
        self.assertNotIn('{CACN', out)

    def test_http_devices(self):
        pw = {'host': 'dev', 'user': 'acme', 'password': 'p'}
        got = self.record('cloudflare_ssl', {'token': 't', 'zone': 'example.com'}, {})
        self.in_order(got, 'GET https://api.cloudflare.com/client/v4/zones/',
                      'has the same names: replacing it', 'PATCH https://api.cloudflare.com/',
                      'SAY replaced the custom certificate')
        got = self.record('cpanel_ssl', {'host': 'cp', 'user': 'u', 'token': 't'}, {})
        self.in_order(got, 'GET https://cp:2083/execute/SSL/installed_hosts',
                      'POST https://cp:2083/execute/SSL/install_ssl',
                      'SAY installed on www.example.com: The SSL certificate is now installed '
                      'onto the domain “www.example.com”')
        got = self.record('directadmin_ssl', dict(pw), {'da_domain': 'example.com'})
        self.in_order(got, 'is the one for www.example.com - replacing it',
                      'dry-run=true', 'SAY replaced the certificate')
        got = self.record('digitalocean_lb', {'token': 't'}, {'load_balancers': 'lb-www'})
        self.in_order(got, 'SAY uploaded acme-', 'PUT https://api.digitalocean.com/v2/'
                      'load_balancers/', 'SAY lb-www:443 uses acme-',
                      'SAY deleted the older acme-www.example.com-')
        got = self.record('f5', dict(pw), {'profiles': '/Common/www_clientssl'})
        self.in_order(got, 'GET https://dev/mgmt/tm/sys/crypto/cert/~Common~acme-www',
                      'SAY installed /Common/acme-',
                      'SAY /Common/www_clientssl: its cert-key-chain entry default holds '
                      '/Common/acme-www.example.com-', 'SAY profile /Common/www_clientssl updated',
                      'SAY deleted the old acme-www.example.com-', 'POST https://dev/mgmt/tm/'
                      'sys/config')
        got = self.record('fastly', {'token': 't'}, {})
        self.in_order(got, 'SAY uploaded the key acme-', 'SAY replaced the certificate',
                      'SAY deleted the older key acme-www.example.com-')
        got = self.record('fortiadc', dict(pw), {'cert_group': 'GRP'})
        self.in_order(got, 'SAY uploaded the local certificate acme-',
                      'SAY the group GRP holds acme-', 'SAY took the older acme-',
                      'SAY deleted the older acme-www.example.com-')
        for ver, said, shape in (('', 'FortiOS 7.4.5', "[{'name'"), ('6.0', 'FortiOS 6.4.15', ''),
                                 ('7.0', 'FortiOS 7.2.10', ''), ('7.4.2', 'FortiOS 7.4.5', '')):
            got = self.record('fortigate', {'host': 'fw', 'token': 't', 'vdom': 'root'},
                              {'vips': 'vip-www'}, version=ver)
            self.in_order(got, 'SAY ' + said, 'SAY imported acme-', 'SAY VIP vip-www uses acme-',
                          'SAY deleted the old acme-www.example.co-')
        got = self.record('fortimanager', {'host': 'fmg', 'token': 't'}, {})
        self.in_order(got, 'SAY added the local certificate acme-',
                      'SAY the CA acme-ca-', 'SAY the GUI and the API use acme-',
                      'SAY deleted the older acme-www.example.co-')
        got = self.record('fortiweb', dict(pw), {'policy': 'www-policy'})
        self.in_order(got, 'SAY imported the local certificate acme-',
                      'SAY the intermediate CA group acme-chain-',
                      'SAY the server policy www-policy uses acme-',
                      'SAY deleted the older acme-www.example.com-')
        got = self.record('hetzner_lb', {'token': 't'}, {'load_balancers': 'lb-www'})
        self.in_order(got, 'SAY uploaded acme-', 'update_service', 'actions/13',
                      'SAY lb-www:443 uses acme-', 'DELETE https://api.hetzner.cloud/v1/'
                      'certificates/101')
        got = self.record('esxi', dict(pw, host_id='host-12', esx_name='esx01'), {},
                          version='8.0.3')
        self.in_order(got, 'SAY vCenter 8.0.3; the host esx01: VMware ESXi 8.0.3',
                      'SAY the host installed the certificate')
        got = self.record('hpe_nimble', dict(pw), {})
        self.assertIn('SAY the HTTPS GUI and the REST API use custom - they reload', got)
        first = self.record('hpe_oneview', dict(pw), {})
        later = self.record('hpe_oneview', dict(pw), {}, later=True)
        self.assertTrue([x for x in first if x.endswith('added to the trust store')], first)
        self.assertTrue([x for x in later if x.endswith('is in the trust store already')], later)

    def test_placeholders_and_masking(self):
        from acmelib.certs import plansandbox as P
        from acmelib.certs import pki

        class B(object):
            cert_pem = pki.self_signed(pki.make_key('ec-256'), ['a.example.test'], days=3)
            names = ['a.example.test', 'b.example.test']
            name = 'a.example.test'
            not_before = 1760000000
            serial = '0a1b2c3d4e5f'
        a = P.Answers([{'url': r'/x$', 'body': {'hosts': '{CERTNAMES}', 'cn': '{CERTNAME}',
                                                'echo': '{SENT:domain}'}}])
        a.bundle, a.options = B(), {}
        got = json.loads(a('POST', 'https://d/x', 'domain=www.example.com&cert=x')[2])
        self.assertEqual(got, {'hosts': ['a.example.test', 'b.example.test'],
                               'cn': 'a.example.test', 'echo': 'www.example.com'})
        names = [a.earlier('{EARLIER%s}' % n) for n in ('', '2', '3')]
        self.assertEqual(len(set(names)), 3)
        self.assertEqual(sorted(names, reverse=True), names)    # each older
        self.assertEqual(P.mask_body(b'grant_type=x&assertion=eyJh.eyJp.c2ln', {})[0],
                         {'grant_type': 'x', 'assertion': '••••'})
        self.assertEqual(P.mask_json({'authLoginDomain': 'LOCAL', 'SessionType': 'API',
                                      'password': 'x'}, {}),
                         {'authLoginDomain': 'LOCAL', 'SessionType': 'API',
                          'password': '••••'})


class RenewalPathsG4(RenewalPathsG2):
    """The renewal path of the targets redfish@ilo .. zimbra (1.0.98): the certificate acme put
    there before found and replaced, the older ones cleaned up, every check shown and every
    decision said - each call answered as the device does (no stand-in answer); FIRST /
    LATER where the first deployment differs."""
    SSH = {'host': 'dev', 'user': 'acme', 'auth': 'password', 'password': 'p'}
    PW = {'host': 'dev', 'user': 'acme', 'password': 'p'}

    def test_lists_replaced_and_cleaned(self):
        got = self.record('sophos', dict(self.PW), {'rules': 'WAF www', 'keep': 1}, later=True)
        self.in_order(got, 'POST https://dev:4444/webconsole/APIController',
                      'SAY uploaded acme-www.example.com-', 'SAY rule WAF www updated (it used '
                      'acme-www.example.com-', 'SAY removed the old acme-www.example.com-')
        first = self.record('sophos', dict(self.PW), {'rules': 'WAF www', 'keep': 1})
        self.assertFalse([x for x in first if 'removed the old' in x])
        got = self.record('unifi_os', dict(self.PW), {}, later=True)
        self.in_order(got, 'POST https://dev/api/auth/login', 'GET https://dev/api/userCertificates',
                      'SAY added acme-', 'PUT https://dev/api/userCertificates/',
                      'SAY deleted the old acme-')
        got = self.record('truenas', dict(self.SSH), {}, later=True)
        self.in_order(got, 'SSH sh -c \'midclt call certificate.query\'',
                      'system.general.config', 'certificate.create', 'SAY imported acme-www_example_com-',
                      'system.general.update', 'ui_restart', 'certificate.delete 4',
                      'SAY deleted the old acme-www_example_com-')
        first = self.record('truenas', dict(self.SSH), {})
        self.assertFalse([x for x in first if 'certificate.delete' in x])
        self.in_order(first, 'SAY imported acme-', 'system.general.update')
        got = self.record('vcd', dict(self.PW), {'cells': 'vcd-cell1'}, later=True)
        self.in_order(got, 'POST https://dev/cloudapi/1.0.0/sessions/provider',
                      'GET https://dev/cloudapi/1.0.0/ssl/certificateLibrary?filter=',
                      'SAY imported acme-', 'SAY vcd-cell1 uses acme-www.example.com-',
                      'PUT https://dev/cloudapi/1.0.0/cells/', 'GET https://dev/api/task/',
                      'GET https://dev/api/task/', '/consumers?',
                      'DELETE https://dev/cloudapi/1.0.0/ssl/certificateLibrary/',
                      'SAY deleted the older acme-')

    def test_http_devices(self):
        got = self.record('synology', dict(self.PW), {}, later=True)
        self.in_order(got, 'POST https://dev:5001/webapi/entry.cgi',
                      'POST https://dev:5001/webapi/entry.cgi?api=SYNO.Core.Certificate&',
                      'SAY replaced "acme www.example.com" (default)')
        got = self.record('virtualmin', dict(self.PW), {'domain': 'example.com'})
        self.in_order(got, 'SAY example.com has another certificate - installing this one',
                      'SAY example.com: certificate installed')
        got = self.record('vault', {'host': 'https://dev:8200', 'token': 't'}, {}, later=True)
        self.in_order(got, 'GET https://dev:8200/v1/secret/data/acme/www.example.com',
                      'SAY acme/www.example.com holds another certificate (version 3)',
                      'SAY wrote acme/www.example.com (version 4)')
        got = self.record('vcenter', dict(self.PW), {}, version='8.0.2')
        self.in_order(got, '/ServiceInstance/content', 'SAY vCenter 8.0.3 - 8.0 U2',
                      'GET https://dev/api/vcenter/certificate-management/vcenter/tls',
                      'SAY vCenter serves CN=www.example.com', 'trusted-root-chains',
                      'PUT https://dev/api/vcenter/certificate-management/vcenter/tls',
                      'DELETE https://dev/api/session')
        got = self.record('vsphere_supervisor', dict(self.PW, supervisor='domain-c8'), {})
        self.in_order(got, 'SAY vCenter 9.1.0: the supervisors/<id>/certificates calls; the '
                      'Supervisor domain-c8 holds another certificate',
                      'PATCH https://dev/api/vcenter/namespace-management/supervisors/')
        got = self.record('vmware_dr', dict(self.PW), {})
        self.in_order(got, 'SAY the appliance holds CN=www.example.com',
                      'POST https://dev:5480/configure/requests/appliance/certificates/server')
        got = self.record('redfish', dict(self.PW), {}, version='ilo')
        self.in_order(got, 'GET https://dev/redfish/v1/', 'SAY iLO 6 firmware 1.62, security '
                      'state Production; it holds', 'SAY key type of the iLO certificate: RSA',
                      'HpeHttpsCert.ImportCertificate', 'SAY imported the certificate with its key')
        self.assertFalse([x for x in got if x.startswith('DELETE')])    # gone with the reset
        from acmelib.certs import runplan as R
        cfg = dict(self.PW, domain='mgmt', _version='')
        rec, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'vcf_component', 'name': 't',
            'op': 'deploy', 'config': cfg, 'options': {}, 'seconds': 30,
            'answers': R.answers_of('vcf_component', cfg, {}),
            'ssh_answers': []}], 'cert': {'names': ['www.example.com'], 'key_type': 'rsa-2048',
                                         'csr_from': 'x'}}, timeout=120)
        evs = rec['r1']['events']
        self.assertFalse(rec['r1'].get('error'))
        self.assertFalse([e for e in evs if e.get('fallback')])
        got = RenewalPaths.seen(evs)
        self.in_order(got, 'SAY the workload domain mgmt is', 'validations',
                      'validations/', 'validations/', 'SAY SDDC Manager validated',
                      '/v1/tasks/', '/v1/tasks/', 'SAY SDDC Manager installed')

    def test_ssh_and_powershell(self):
        got = self.record('zimbra', dict(self.SSH), {}, later=True)
        self.in_order(got, 'SSH sh -c \'sha256sum ', 'SAY /opt/zimbra/ssl/zimbra/commercial/'
                      'commercial.key: SHA-256 there', 'SAY the files replaced kept as',
                      'zmcertmgr verifycrt', 'zmcertmgr deploycrt', 'zmcontrol restart')
        got = self.record('traefik', dict(self.SSH), {}, later=True)
        self.in_order(got, 'not there yet - written', 'SHA-256 there',
                      'SSH sh -c \'ls -1 /etc/traefik/certs', 'SAY deleted the old acme-')
        first = self.record('traefik', dict(self.SSH), {})
        self.assertFalse([x for x in first if 'SHA-256 there' in x])
        got = self.record('unity', dict(self.SSH), {})
        self.in_order(got, 'SAY Unisphere serves another certificate', 'SSH svc_custom_cert acmecert',
                      'SSH rm -f ', 'SAY installed')
        got = self.record('windows_ssh', dict(self.SSH),
                          {'iis': 'Default Web Site | www.example.com | 443', 'rdp': True})
        self.in_order(got, 'SAY bound to IIS Default Web Site www.example.com:443',
                      'SAY Remote Desktop listener uses it', 'SAY removed the old 5A0E')
        got = self.record('windows_scom', dict(self.SSH), {})
        self.in_order(got, 'SAY imported', 'SAY Operations Manager uses it (www.example.com)',
                      'SAY restarted HealthService', 'SAY removed the old 5A0E')
        got = self.record('veeam_vbr', dict(self.SSH), {'allow_leaf': True,
                                                         'restart_services': 'VeeamBackupSvc'},
                          version='12.3')
        self.in_order(got, 'SAY Veeam Backup & Replication 12.3.1.1139; its backup server '
                      'certificate now: 5A0E', 'SAY imported the certificate into LocalMachine',
                      'SAY the backup server certificate is set', 'SAY the REST API (0.0.0.0:9419)',
                      'SAY removed the old 5A0E', 'SAY restarted VeeamBackupSvc')

    def test_windows_roles(self):
        """windows_ssh with each role on: the role's own steps on the renewal path."""
        want = {
            'rds': ['SAY RDS RDGateway uses it', 'SAY RDS RDRedirector uses it'],
            'rdgw': ['SAY read on the key for NT AUTHORITY\\NETWORK SERVICE',
                     'SAY RD Gateway uses it', 'SAY restarted TSGateway'],
            'adfs': ['SAY AD FS SSL uses it', 'SAY AD FS Service-Communications uses it',
                     'SAY restarted adfssrv'],
            'wap': ['SAY Web Application Proxy uses it', 'SAY WAP application'],
            'sql': ['SAY read on the key for NT Service\\MSSQLSERVER',
                    'SAY SQL Server MSSQLSERVER uses it', 'SAY restarted MSSQLSERVER'],
            'ldaps': ['SAY LDAPS: put into NTDS', 'SAY LDAPS: the old',
                      'SAY LDAPS: the domain controller took'],
            'winrm': ['SAY WinRM Listener_', 'SAY restarted WinRM'],
            'sstp': ['SAY SSTP uses it', 'SAY restarted RemoteAccess'],
            'ccs': ['SAY CCS: wrote www.example.com.pfx'],
            'ftp': ['SAY FTP (every site) uses it'],
            'exchange': ['SAY Exchange uses it for IIS, SMTP'],
            'lync': ['SAY Skype for Business Default uses it'],
            'sharepoint': ['SAY SharePoint: imported', 'SAY SharePoint: https://sp.example.com'],
            'wac': ['SAY Windows Admin Center uses it', 'SAY restarted WindowsAdminCenter']}
        from acmelib.plugins.targets import _win_roles as WR
        self.assertEqual(sorted(want), sorted(r[0] for r in WR.ROLES))
        for role, lines in sorted(want.items()):
            got = self.record('windows_ssh', dict(self.SSH), {
                'role_' + role: True, 'ccs_path': '\\\\fs\\ccs', 'ccs_password': 'p',
                'sp_url': 'https://sp.example.com', 'wap_apps': True})
            self.in_order(got, 'SAY roles on the server', *(lines + ['SAY removed the old 5A0E']))


class SandboxPlaceholdersG4(unittest.TestCase):
    """What the answers of the targets redfish@ilo .. zimbra need of the sandbox (1.0.98)."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def test_names_label_and_seen(self):
        from acmelib.certs import plansandbox as P
        from acmelib.plugins.targets import _common as C

        class B(object):
            name, names, not_before, serial = 'www', ['www.example.com'], 1786000000.0, 'ab12cd34ef'
        a = P.Answers([{'method': 'POST', 'url': r'/x$', 'body':
                        '<a>{CURRENT:50:6}</a><b>{EARLIER:50:6}</b><c>{EARLIER2:63:8:_}</c>'
                        '<d>acme {LABEL}</d><e>{SEEN:criteria="=">([^<]*)<}</e>'}])
        a.bundle, a.options = B(), {}
        st, hd, raw = a('POST', 'https://h/x', '<key name="Name" criteria="=">WAF www</key>')
        got = raw.decode()
        cur = C.object_name(B(), {}, 50, 6)
        self.assertIn('<a>%s</a>' % cur, got)
        prefix = C.name_prefix(B(), {}, 50, 6)
        old = got.split('<b>')[1].split('</b>')[0]
        self.assertTrue(C.ours(old, prefix) and old != cur, old)
        self.assertNotIn('.', got.split('<c>')[1].split('</c>')[0])
        self.assertIn('<d>acme www</d><e>WAF www</e>', got)
        # SSH: one line a thing asked (seen_lines - this command only), a PowerShell script
        # matched decoded
        import base64
        a = P.Answers([], [{'command': r'sha256sum ', 'seen_lines': True, 'stdout': ''.join(
            'h%d  {SEEN:sha256sum (?:[^\\s\']+ ){%d}(/[^\\s\';]*)}\n' % (i, i) for i in range(5))},
            {'command': r'powershell', 'script': r'IMPORTED', 'stdout': 'IMPORTED x\n'}])
        self.assertEqual(a.ssh("sh -c 'sha256sum /a /b 2>/dev/null; true'")[1], 'h0  /a\nh1  /b\n')
        enc = base64.b64encode("Write-Output 'IMPORTED'".encode('utf-16-le')).decode()
        self.assertEqual(a.ssh('powershell.exe -EncodedCommand ' + enc)[1], 'IMPORTED x\n')
        self.assertIsNone(a.ssh('powershell.exe -EncodedCommand ' + base64.b64encode(
            'Get-Date'.encode('utf-16-le')).decode()))

    def test_seen_lines_if_all_optional(self):
        from acmelib.certs import plansandbox as P
        a = P.Answers([], [{'command': r'x', 'seen_lines': True, 'stdout':
                            "A {SEENALL:'(\\w+)'}\nB{IF:SMTP}\nC{IF:POP}\nD{SEEN?:(zz)}\n"}])
        self.assertEqual(a.ssh("x 'IIS', 'SMTP'")[1], 'A IIS, SMTP\nB\nD\n')

    def test_xml_secrets_masked(self):
        from acmelib.certs import plansandbox as P
        t = P.mask_text('<Login><Username>a</Username><Password>pw1</Password></Login>'
                        '<key name="Name">WAF</key><Certificate><Password>p12pw</Password>'
                        '</Certificate>', {})
        self.assertNotIn('pw1', t)
        self.assertNotIn('p12pw', t)
        self.assertIn('<key name="Name">WAF</key>', t)
        self.assertIn('<Username>a</Username>', t)


class SourcesAndValidations(unittest.TestCase):
    """The sources and validations (1.0.98): each recorded as on a running account - the zone
    there, the record put in, seen by every name server (the sandbox's DNS answers), taken
    away again; a CA's answer holds a certificate for the request's key; a commercial CA's
    DCV put in place by the certificate's own validation within the source's run; nothing
    goes around ctx; secrets of a key's shape handed as throwaway keys of that shape."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def run_one(self, family, kind, cfg, names=('www.example.com',), key_type='ec-256',
                dcv=None, settings=None, previous=False, cert_id=None):
        from acmelib.certs import runplan as R
        from acmelib.certs import plansources as PS
        from acmelib.plugins import base
        base.REGISTRY.reload()
        cls = base.REGISTRY.get(family, kind)
        full = {f['key']: f.get('default') for f in cls.fields or [] if f.get('key')
                and f.get('default') not in (None, '')}
        full.update(cfg)
        sec = R.Secrets()
        scfg, marks = sec.stand_ins(R._fields_of(cls), full)
        r = {'id': 'r1', 'family': family, 'kind': kind, 'name': kind, 'seconds': 30,
             'op': 'issue' if family == 'issuer' else 'challenge', 'config': scfg,
             'marks': marks, 'answers': R.answers_of(kind, scfg, first=False, family=family),
             'ssh_answers': R.ssh_answers_of(kind, scfg, family=family), 'names': list(names),
             'pinned': PS.PINNED.get(kind, []), 'previous': previous}
        if dcv:
            ck, ccfg = dcv
            ccls = base.REGISTRY.get('challenge', ck)
            c2, m2 = sec.stand_ins(R._fields_of(ccls), ccfg)
            r['marks'] = dict(marks, **m2)
            r['challenges'] = {n: {'kind': ck, 'name': ck, 'config': c2,
                                   'answers': R.answers_of(ck, c2, first=False,
                                                           family='challenge'),
                                   'ssh_answers': R.ssh_answers_of(ck, c2, family='challenge')}
                               for n in names}
        got, err = R.record({'runs': [r], 'settings': settings or {},
                             'cert': {'names': list(names), 'key_type': key_type,
                                      'id': cert_id}}, timeout=120)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), '%s: %s' % (kind, run.get('error')))
        evs = run['events']
        self.assertFalse([e for e in evs if e.get('kind') == 'bypass'], kind)
        self.assertFalse([e for e in evs if e.get('fallback')],
                         '%s: unanswered %s' % (kind, [e.get('url') for e in evs
                                                       if e.get('fallback')]))
        return evs, sec

    @staticmethod
    def lines(evs):
        out = []
        for e in evs:
            if e['kind'] == 'http':
                out.append('%s %s' % (e['method'], e['url']))
            elif e['kind'] == 'say':
                out.append('SAY ' + e['words'])
            elif e['kind'] in ('dns-ask', 'phase', 'command', 'ssh-run'):
                out.append('%s %s' % (e['kind'], e.get('name') or e.get('what') or
                                      e.get('command') or ' '.join(e.get('argv') or [])))
        return out

    def test_dns_providers_take_the_renewal_path(self):
        """The zone listed, ours not there yet - put in, seen by every name server, the record
        listed again at the cleanup and deleted by its id."""
        evs, _s = self.run_one('challenge', 'cloudflare', {'token': 'CfTok3nVerySecret'})
        got = self.lines(evs)
        i = got.index('GET https://api.cloudflare.com/client/v4/zones?name=example.com')
        self.assertTrue(got[i + 1].startswith('POST https://api.cloudflare.com/client/v4/zones/'))
        self.assertIn('SAY _acme-challenge.www.example.com TXT is on every name server of '
                      'example.com (ns1.example.com, ns2.example.com)', got)
        self.assertTrue(got[-1].startswith('DELETE https://api.cloudflare.com/'), got[-1])
        for kind, cfg in (('hetzner', {'token': 't0k3n-hetzner-xyz'}),
                          ('route53', {'access_key_id': 'AKIAEXAMPLE',
                                       'secret_access_key': 'secretsecretsecret'}),
                          ('cpanel', {'host': 'cp.example.com', 'user': 'u',
                                      'token': 'tok3n-cpanel-xyz'}),
                          ('loopia', {'user': 'u@loopiaapi', 'password': 'pw-loopia-xyz'}),
                          ('subreg', {'login': 'u', 'password': 'pw-subreg-xyz'})):
            evs, _s = self.run_one('challenge', kind, cfg)
            phases = [e.get('what') for e in evs if e['kind'] == 'phase']
            self.assertEqual(phases, ['ready', 'cleanup'], kind)
            said = [e['words'] for e in evs if e['kind'] == 'say']
            self.assertTrue([w for w in said if 'on every name server' in w], (kind, said))

    def test_http01_and_scripts(self):
        evs, _s = self.run_one('challenge', 'http_webdav', {'url': 'https://web.example.com',
                                                            'user': 'u', 'password': 'pw-dav'})
        said = [e['words'] for e in evs if e['kind'] == 'say']
        self.assertIn('http://www.example.com/.well-known/acme-challenge/PLAN-TOKEN-from-the-CA-'
                      '0000000000 answers with the right value', said)
        evs, _s = self.run_one('challenge', 'script', {'path': '/bin/true'})
        cmds = [e['argv'][:2] for e in evs if e['kind'] == 'command']
        self.assertEqual(cmds, [['/bin/true', 'present'], ['/bin/true', 'cleanup']])
        evs, _s = self.run_one('challenge', 'dns_builtin', {}, settings={
            'dns_zone': 'acme.example.net', 'dns_server': 1})
        said = [e['words'] for e in evs if e['kind'] == 'say']
        self.assertIn('_acme-challenge.www.example.com is a CNAME to '
                      'www.example.com.acme.example.net, as it should be', said)

    def test_shaped_secrets(self):
        """A service account's JSON and a private JWK are handed as throwaway keys of their
        shape; the other secrets in the JSON as stand-ins."""
        from acmelib.certs import pki
        from acmelib.certs import runplan as R
        real = pki.make_key('rsa-2048')
        sa = json.dumps({'type': 'service_account', 'project_id': 'p1', 'private_key_id':
                         'kid-very-secret-1', 'private_key': real,
                         'client_email': 'a@p1.iam.gserviceaccount.com',
                         'token_uri': 'https://oauth2.googleapis.com/token'})
        sec = R.Secrets()
        out, marks = sec.stand_ins([{'key': 'service_account', 'type': 'secret'}],
                                   {'service_account': sa})
        got = json.loads(out['service_account'])
        self.assertNotEqual(got['private_key'], real)
        self.assertIn('PRIVATE KEY', got['private_key'])
        self.assertNotEqual(got['private_key_id'], 'kid-very-secret-1')
        self.assertEqual(got['token_uri'], 'https://oauth2.googleapis.com/token')
        self.assertEqual(got['client_email'], 'a@p1.iam.gserviceaccount.com')
        jwk = json.dumps({'kty': 'EC', 'crv': 'P-256', 'kid': 'k1', 'x': 'a', 'y': 'b',
                          'd': 'real-d'})
        out, _m = sec.stand_ins([{'key': 'k', 'type': 'secret'}], {'k': jwk})
        j = json.loads(out['k'])
        self.assertEqual((j['kty'], j['crv'], j['kid']), ('EC', 'P-256', 'k1'))
        self.assertNotEqual(j['d'], 'real-d')
        self.assertEqual(len(j['d']), 43)
        # a signed token's signature never shows
        text = R.scrub({'t': 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ'},
                       set())['t']
        self.assertTrue(text.startswith('eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.'), text)
        self.assertNotIn('c2lnbmF0dXJl', text)

    def test_cas_of_ones_own(self):
        evs, _s = self.run_one('issuer', 'vault_pki', {'url': 'https://vault:8200',
                                                       'token': 'hvs.secret', 'role': 'web'})
        self.assertTrue([e for e in evs if e['kind'] == 'say' and
                         e['words'].startswith('the certificate came: serial ')])
        evs, _s = self.run_one('issuer', 'est', {'url': 'https://est.example.com', 'user': 'u',
                                                 'password': 'pw-est'})
        self.assertEqual([e['url'].rsplit('/', 1)[1] for e in evs if e['kind'] == 'http'],
                         ['simpleenroll', 'cacerts'])

    def test_adcs_ntlm_through_ctx(self):
        """Web Enrollment signed in with NTLM on one connection kept through ctx: the three
        messages recorded, none around ctx, the Authorization masked."""
        evs, _s = self.run_one('issuer', 'ms_adcs', {
            'url': 'https://ca01.example.local/certsrv', 'user': 'svc', 'password': 'Pw-AdCs-1',
            'domain': 'EXAMPLE', 'template': 'WebServer', 'ca_pem': ''})
        http = [e for e in evs if e['kind'] == 'http']
        self.assertEqual([(e['method'], e['answer']) for e in http],
                         [('POST', 401), ('POST', 401), ('POST', 200), ('GET', 200),
                          ('GET', 200)])
        self.assertTrue(all(e.get('kept') for e in http))
        self.assertEqual(http[1]['headers'].get('Authorization'), 'NTLM ••••')

    def test_scep_and_cmp(self):
        evs, _s = self.run_one('issuer', 'scep', {
            'url': 'https://ndes.example.local/certsrv/mscep/mscep.dll', 'ca_fingerprint':
            'ab' * 32, 'challenge': 'S3cret-scep'}, key_type='rsa-2048')
        ops = [e['url'].split('operation=')[1].split('&')[0] for e in evs if e['kind'] == 'http']
        self.assertEqual(ops, ['GetCACaps', 'GetCACert', 'PKIOperation'])
        from acmelib.certs import pki
        root = pki.self_signed(pki.make_key('ec-256'), [], subject={'CN': 'R'}, days=30,
                               is_ca=True)
        evs, _s = self.run_one('issuer', 'cmp', {'url': 'https://ca.example.com/pkix/',
                                                 'trusted': root, 'reference': 'r1',
                                                 'secret': 'Cmp-Secret-1'})
        cmd = [e['argv'] for e in evs if e['kind'] == 'command']
        self.assertEqual(cmd[0][:2], ['openssl', 'cmp'])
        self.assertNotIn('Cmp-Secret-1', json.dumps(evs))

    def test_commercial_dcv_in_the_source(self):
        """DigiCert: the order reissued, its DCV record put in by the certificate's validation
        (Cloudflare), seen, checked, the certificate downloaded, the record taken away."""
        evs, _s = self.run_one('issuer', 'digicert', {
            'api_key': 'Dc-Key-Very-Secret', 'order_id': '12345678', 'product': 'ssl_basic',
            'dcv': 'dns-txt'}, dcv=('cloudflare', {'token': 'CfTok3nVerySecret'}))
        got = [x for x in self.lines(evs) if not x.startswith('dns-ask')]
        want = ['POST https://www.digicert.com/services/v2/order/certificate/12345678/reissue',
                'PUT https://www.digicert.com/services/v2/order/certificate/12345678/'
                'dcv-random-value', 'SAY _dnsauth.www.example.com TXT "', 'SAY _dnsauth.www.'
                'example.com TXT is on every name server', '/check-dcv',
                '/download/format/pem_all', 'SAY the certificate came', 'DELETE https://api.'
                'cloudflare.com/']
        at = 0
        for w in want:
            hit = [i for i in range(at, len(got)) if w in got[i]]
            self.assertTrue(hit, '%s not after %d in %s' % (w, at, got))
            at = hit[0] + 1
        self.assertNotIn('Dc-Key-Very-Secret', json.dumps(evs))
        self.assertNotIn('CfTok3nVerySecret', json.dumps(evs))

    CF = ('cloudflare', {'token': 'CfTok3nVerySecret'})

    def test_commercial_sources_reissue_with_dcv(self):
        """Each commercial source on its renewal path: the order bought before reissued
        (rekeyed, renewed), its DCV put in by the certificate's validation where the CA asks
        for one, the order read until issued, the certificate for the request's key."""
        cases = [
            ('gogetssl', {'user': 'u', 'api_password': 'Gg-Pass-1', 'order_id': '1234567',
                          'dcv': 'dns'}, self.CF, 'reissue inside order 1234567'),
            ('ssls', {'token': 'Ssls-Token-1', 'cert_reuse': '1234567890', 'dcv': 'dns',
                      'product': 'RapidSSL',
                      'policy': 'reissue'}, self.CF, 'the certificate 1234567890 is reissued'),
            ('namecheap_ssl', {'api_user': 'u', 'api_key': 'Nc-Key-1', 'client_ip':
                               '203.0.113.10', 'cert_id': '1234567', 'admin_email':
                               'it@example.com', 'dcv': 'cname'}, self.CF,
             'reissue of certificate 1234567'),
            ('certum', {'user': 'partner', 'password': 'Certum-Pw-1', 'order_id': '4711815',
                        'dcv': 'DNS_TXT_PREFIX'}, self.CF, 'reissue inside order 4711815'),
            ('globalsign_mssl', {'user': 'u', 'password': 'Gs-Pw-1', 'order_id':
                                 'CE20260101000001', 'profile_id': 'MSSL1234', 'dcv': 'profile'},
             self.CF, 'reissue of order CE20260101000001'),
            ('sslmarket', {'token': 'Sm-Token-1', 'order_id': '123456', 'product': 'RapidSSL',
                           'dcv': 'DNS', 'policy': 'reissue'}, self.CF,
             'reissue of order 123456 asked for'),
            ('sslcom', {'account_key': 'ak', 'secret_key': 'Sc-Secret-1', 'order_ref':
                        'co-ac1ecm200', 'dcv': 'http'},
             ('http_ssh', {'hosts': ['web1.example.com'], 'user': 'acme', 'key': 'k'}),
             'rekeyed with acme\'s request'),
            ('sectigo_scm', {'client_id': 'c', 'client_secret': 'Sec-Secret-1',
                             'ssl_id': '112233', 'org_id': '1234', 'customer_uri': 'example',
                             'dcv': 'cname'}, self.CF, 'SCM renews certificate 112233'),
            ('sslstore', {'partner_code': '12345678', 'auth_token': 'Ss-Token-1',
                          'order_id': 'TSSL-9876543', 'dcv': 'cname'}, self.CF,
             'reissue inside order TSSL-9876543')]
        for kind, cfg, dcv, said in cases:
            evs, _s = self.run_one('issuer', kind, cfg, dcv=dcv)
            words = [e['words'] for e in evs if e['kind'] == 'say']
            self.assertTrue([w for w in words if said in w], (kind, words))
            self.assertTrue([w for w in words if w.startswith('the certificate came')],
                            (kind, words))
            for v in cfg.values():
                if 'Secret' in v or 'Pw' in v or 'Token' in v or 'Key-' in v or 'Pass' in v:
                    self.assertNotIn(v, json.dumps(evs), kind)

    def test_acme_source_underneath(self):
        """SSLmarket ACME: its ACME key made through SSLmarket's API, then the ACME order with
        the certificate's own validation in the source's run."""
        evs, _s = self.run_one('issuer', 'sslmarket_acme', {
            'token': 'Sm-Token-1', 'acme_product': 'RapidSSLDV_ACME', 'acme_name': 'acme',
            'contacts': 'it@example.com'}, dcv=self.CF)
        urls = [e['url'].rsplit('/', 2)[-1] for e in evs if e['kind'] == 'http' and
                'cloudflare' not in e['url']]
        for want in ('acme', 'new-account', 'new-order', '1', 'dns', 'finalize'):
            self.assertIn(want, urls)
        self.assertTrue([e for e in evs if e['kind'] == 'say' and
                         'is on every name server' in e['words']])

    def test_venafi_renews_in_place(self):
        """A renewal (the certificate before, what the first issue kept): Venafi renews the
        certificate it made in place - the DN, the certificate id."""
        evs, _s = self.run_one('issuer', 'venafi_tpp', {
            'url': 'https://tpp.example.com', 'user': 'u', 'password': 'Tpp-Pw-1',
            'zone': 'Certificates\\\\Web'}, previous=True, cert_id=42)
        self.assertTrue([e for e in evs if e['kind'] == 'http' and
                         e['url'].endswith('/vedsdk/certificates/renew')])
        evs, _s = self.run_one('issuer', 'venafi_cloud', {
            'api_key': 'Vc-Key-1', 'application': 'Storefront', 'template': 'Default'},
            previous=True, cert_id=42)
        self.assertTrue([e for e in evs if e['kind'] == 'say' and
                         e['words'].startswith('the service took the renewal of ')])



class RenewalPathsG1(unittest.TestCase):
    """The renewal path of the targets a10 .. cisco_nxos (1.0.98): what is there found and
    said, replaced, the older ones cleaned up - every call answered as the device does; what
    acme keeps for a target (the acme push pin, ACM's ARN) and acme's own pages as they are;
    a password made for the run masked."""
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def record(self, kind, cfg, opts=None, version='', later=False, run=None, job=None,
               events=False):
        from acmelib.certs import runplan as R
        cfg = dict(cfg, _version=version)
        r = dict({'id': 'r1', 'family': 'target', 'kind': kind, 'name': 't', 'op': 'deploy',
                  'config': cfg, 'options': opts or {}, 'seconds': 30,
                  'answers': R.answers_of(kind, cfg, opts, first=not later, later=later,
                                          version=version),
                  'ssh_answers': R.ssh_answers_of(kind, cfg, opts, version=version)},
                 **(run or {}))
        got, err = R.record(dict({'runs': [r], 'cert': {'names': ['www.example.com'],
                                                        'key_type': 'rsa-2048'}}, **(job or {})),
                            timeout=120)
        self.assertEqual(err, '')
        out = got['r1']
        self.assertFalse(out.get('error'), '%s: %s' % (kind, out.get('error')))
        evs = out['events']
        self.assertFalse([e for e in evs if e.get('fallback')],
                         '%s: a call no answer of the module matched' % kind)
        return evs if events else RenewalPaths.seen(evs)

    def in_order(self, lines, *wants):
        """In this order - two in a row may be in the same line (a step and its words)."""
        i = 0
        for w in wants:
            while i < len(lines) and w not in lines[i]:
                i += 1
            self.assertLess(i, len(lines), '%r not found in order in %s' % (w, lines))

    def test_http_devices(self):
        pw = {'host': 'dev', 'user': 'acme', 'password': 'p'}
        got = self.record('a10', pw, {'templates': 'tpl-www'})
        self.in_order(got, 'GET https://dev/axapi/v3/file/ssl-cert/oper',
                      'SAY imported the certificate and key acme-www.example.com-',
                      'SAY the chain acme-ca-', 'SAY the client-SSL template tpl-www uses',
                      'DELETE https://dev/axapi/v3/slb/template/client-ssl/tpl-www/certificate/'
                      'acme-www.example.com-', 'SAY wrote the configuration',
                      'SAY deleted the older acme-www.example.com-')
        got = self.record('aria_lifecycle', pw, {'products': 'env1 vrops'})
        self.in_order(got, 'POST https://dev/lcm/locker/api/v2/certificates/import',
                      'pre-validate', 'SAY vrops uses acme-',
                      'SAY deleted the older acme-www.example.com-')
        got = self.record('aruba_aoscx', pw, {})
        self.in_order(got, 'SAY the trust anchor profile acme-ca-',
                      'SAY installed the certificate acme-',
                      'SAY https-server uses acme-www.example-2', '(before: acme-www.example-',
                      'SAY saved the configuration', 'SAY deleted the older acme-www.example-')
        got = self.record('avi', pw, {'virtual_services': 'vs-www'})
        self.in_order(got, 'SAY the CA certificate acme-ca-', 'SAY added acme-',
                      'SAY vs-www uses acme-', '(before: acme-www.example.com-',
                      'SAY deleted the older acme-www.example.com-')
        got = self.record('barracuda_waf', pw, {'service': 'www-https'})
        self.in_order(got, 'SAY uploaded the certificate acme-',
                      'SAY the service www-https uses acme-', 'SAY deleted the older acme-')
        got = self.record('barracuda_cgf', {'host': 'dev', 'token': 't'}, {'entry': 'vpn'})
        self.in_order(got, 'SAY the entry vpn holds another certificate',
                      'PUT https://dev:8443/rest/config/v1/box/store/certificates/vpn',
                      'SAY imported the certificate into vpn')
        got = self.record('checkpoint', pw, {'https_rule': 'Inbound www',
                                             'https_layer': 'Default Layer'})
        self.in_order(got, 'SAY imported the server certificate acme-',
                      'SAY the HTTPS Inspection rule Inbound www uses acme-',
                      'SAY deleted the older acme-', 'SAY publishing: succeeded')
        got = self.record('cisco_asa', pw, {'trust_points': 'outside'})
        self.in_order(got, 'SAY imported into the new trustpoint acme-',
                      'SAY ssl trust-point acme-', '(before: acme-www.example.com-',
                      'SAY removed the older trustpoint acme-', 'SAY write memory')
        got = self.record('cisco_ftd_fdm', pw, {'ravpn': True})
        self.in_order(got, 'SAY the CA certificate acme-ca-', 'SAY the web interface uses acme-',
                      'SAY the RA VPN RAVPN uses acme-', 'SAY deployed (',
                      'SAY deleted the older acme-')
        got = self.record('cisco_ise', dict(pw, node='ise01'), {})
        self.in_order(got, 'SAY the node has the earlier acme-', 'is not imported (there already',
                      'SAY imported acme-', 'SAY deleted the old acme-')
        got = self.record('cisco_nxos', pw, {})
        self.in_order(got, 'SAY imported into the new trustpoint acme-',
                      'SAY NX-API uses acme-', 'SAY removed the older trustpoint acme-')
        got = self.record('cisco_fmc', pw, {'decryption_policy': 'Inbound', 'enrollment':
                                            'RAVPN-acme', 'enroll_devices': 'ftd-1'},
                          version='7.7', later=True)
        self.in_order(got, 'GET https://dev/api/fmc_platform/v1/info/serverversion',
                      'SAY replaced the PKCS#12 of the Cert Enrollment',
                      'SAY RE_ENROLL of', 'SAY the rule decrypt-www of Inbound uses acme-',
                      '(before: acme-www.example.com-', 'SAY deployment asked for ftd-1',
                      'SAY deleted the older acme-')
        got = self.record('cisco_imc', pw, {})
        self.in_order(got, 'SAY the IMC took the external certificate',
                      'SAY the external certificate is activated')

    def test_cloud(self):
        az = {'subscription_id': 's', 'resource_group': 'rg', 'tenant_id': 't',
              'client_id': 'c', 'client_secret': 'x'}
        got = self.record('azure_appgw', az, {'gateway': 'agw', 'listener': 'https-www'})
        self.in_order(got, 'SAY the listener https-www uses acme-', '(before: acme-',
                      'SAY the gateway agw is being updated', 'SAY the gateway agw is updated',
                      'SAY took the older acme-')
        got = self.record('azure_appservice', az, {'site': 'app', 'hostnames': 'www.example.com'})
        self.in_order(got, 'SAY uploaded acme-', 'SAY www.example.com uses acme-',
                      'before: the certificate 5A0E1D2C', 'SAY deleted the older acme-')
        got = self.record('azure_keyvault', dict(az, vault='kv-firma'), {}, later=True)
        self.in_order(got, 'SAY the vault has acme-www-example-com, version',
                      'POST https://kv-firma.vault.azure.net/certificates/acme-www-example-com/'
                      'import', 'SAY imported into acme-www-example-com as version')
        got = self.record('azure_keyvault', dict(az, vault='kv-firma'), {})
        self.in_order(got, 'SAY the vault has no certificate acme-www-example-com yet')
        got = self.record('aruba_central', {'client_id': 'c', 'client_secret': 'x',
                                            'refresh_token': 'r'}, {'cert_name': 'cp'},
                          later=True)
        self.in_order(got, 'SAY cp is in Central', 'PUT https://apigw-prod2',
                      'SAY replaced cp into Central')
        got = self.record('bunny', {'api_key': 'k'}, {'pull_zone': 'zone',
                                                      'hostnames': 'cdn.example.com'})
        self.in_order(got, 'SAY cdn.example.com has the certificate (in place of the one it had)')
        # ACM: the ARN acme kept from the first import - the renewal re-imports into it
        from acmelib.plugins.targets.aws_acm import AwsAcmTarget as cls
        aws = {'access_key_id': 'AKIAX', 'secret_access_key': 's', 'region': 'eu-central-1'}

        class B(object):
            name = 'www.example.com'
            names = ['www.example.com']
            key_type = 'rsa-2048'
        from acmelib.plugins.targets import aws_acm as A
        key = cls(dict(aws), None).kv_arn(B, {}) + ':' + A.acm_key_type(B)
        arn = 'arn:aws:acm:eu-central-1:123456789012:certificate/kept'
        got = self.record('aws_acm', aws, {}, run={'kv': {key: arn}})
        self.in_order(got, 'SAY %s holds another certificate (serial' % arn,
                      'SAY re-imported into %s' % arn)
        self.in_order(self.record('aws_acm', aws, {}), 'SAY imported as arn:aws:acm:')

    def test_ssh_and_own(self):
        ssh = {'host': 'dev', 'user': 'acme', 'auth': 'password', 'password': 'p'}
        for ver, said in (('', 'IOS XE 17.12.4'), ('17.3', 'IOS XE 17.9.5'),
                          ('17.12', 'IOS XE 17.12.4')):
            got = self.record('cisco_iosxe', ssh, {}, version=ver)
            self.in_order(got, 'SSH show version', 'SAY %s; trustpoints: TP-self-signed' % said,
                          'SAY imported into the new trustpoint acme-',
                          'SAY the HTTPS server uses acme-', 'SAY write memory - [OK]',
                          'SAY removed the older trustpoint acme-www.example.com-')
        evs = self.record('aruba_aos8', dict(ssh, stage_host='tftp', stage_auth='password',
                                             stage_password='q'), {}, events=True)
        got = RenewalPaths.seen(evs)
        self.in_order(got, 'SAY the controller has the earlier ServerCert acme-',
                      'SAY the TrustedCA acme-ca-', 'SAY imported the ServerCert acme-',
                      'SAY write memory', 'SAY removed the older ServerCert acme-')
        # the one-time PKCS#12 password typed in is a secret: masked
        imp = [e for e in evs if e['kind'] == 'ssh-run' and 'pki-import pfx' in
               json.dumps(e.get('input'))]
        self.assertTrue(imp, evs)
        self.assertIn('(a password made for this run)', json.dumps(imp))
        got = self.record('aria_automation', ssh, {})
        self.in_order(got, 'SSH sh -c \'vracli certificate ingress --list\'',
                      'SAY the ingress certificate there now is another one',
                      'SAY vracli set the ingress certificate', 'SAY deploy.sh finished')
        got = self.record('caddy', ssh, {})
        self.in_order(got, 'SAY Caddy has 2 certificates loaded through its API, 1 tagged '
                      'acme-www.example.com - replaced', 'SAY Caddy took the certificate')
        got = self.record('caddy', ssh, {'mode': 'files', 'cert_file': '/c/x.crt',
                                         'key_file': '/c/x.key'})
        self.in_order(got, 'SAY /c/x.crt: SHA-256 there 5a0e1d2c', 'SAY the files replaced kept',
                      'SAY ran caddy reload')
        # acme push: paired already (the pin acme keeps) - no pairing, the install; with a
        # pairing code and no pin, the pairing goes through first
        from acmelib.certs import runplan as R
        got = self.record('acme_push', {'url': 'https://otp.example/admin/'}, {},
                          run={'push_pin': dict(R.PUSH_PIN)})
        self.assertFalse([x for x in got if 'acme-push-pair' in x], got)
        self.in_order(got, 'GET https://otp.example/admin/?api=acme-push-hello',
                      'is the application paired', 'POST https://otp.example/admin/?api='
                      'acme-push-install', 'SAY node:otp1')
        got = self.record('acme_push', {'url': 'https://otp.example/admin/',
                                        'pair_code': 'ABCD-EFGH'}, {})
        self.in_order(got, 'acme-push-pair', 'SAY paired with otp', 'acme-push-install')
        # acme's own pages as they are: each node and the VIP address, what each holds
        pages = {'where': {'node': 'a1', 'nodes': ['a1', 'a2'], 'cluster': True,
                           'vip': {'on': True, 'fqdn': 'www.example.com', 'address': ''}},
                 'have': {'a1': {'fingerprint': 'ab', 'cn': 'a1.example.com',
                                 'not_after': 1790000000, 'how': 'by hand'}}}
        evs = self.record('appliance', {}, {}, job={'pages': pages}, events=True)
        got = RenewalPaths.seen(evs)
        self.in_order(got, 'SAY the pages of a1 have a1.example.com until', 'SAY the pages of a1 '
                      'take', 'SAY the pages of a2 have no certificate of their own yet',
                      'SAY the pages of the VIP address')
        self.assertEqual([e['where'] for e in evs if e['kind'] == 'pages'], ['a1', 'a2', 'vip'])

    def test_instant_ap_cli_said(self):
        """Instant AP (every version): the lines typed into its CLI are the step's words and
        command - not an empty command; the way the version takes is said; every call answered,
        the one-time password masked."""
        from acmelib.certs import runplan as R
        cfg = {'host': 'iap', 'user': 'admin', 'auth': 'password', 'password': 'p',
               'stage_host': 'tftp', 'stage_addr': '192.0.2.10'}
        for ver, way, line in (('', 'Instant 8.10.0.6: the certificate imported',
                                'crypto pki-import format pfx'),
                               ('8.7', 'Instant 8.10.0.6: the certificate imported',
                                'pki-cert-assign application ui'),
                               ('8.3', 'Instant 8.6.0.18: loaded with copy tftp',
                                'copy tftp 192.0.2.10 acme-')):
            evs = self.record('aruba_iap', cfg, {}, version=ver, events=True)
            self.in_order(RenewalPaths.seen(evs), 'SAY ' + way, 'rm -f -- /srv/tftp/acme-')
            words = [st['words'] for st in R.steps_of(evs)]
            cli = [w for w in words if w.startswith('In the CLI of iap: ')]
            self.assertIn('In the CLI of iap: show version', cli)
            self.assertTrue([w for w in cli if line in w], cli)
            self.assertFalse([w for w in words if w == 'Runs a command on iap'], words)
            self.assertTrue(all('psk' not in w or '(a password made for this run)' in w
                                for w in cli), cli)

    def test_what_acme_keeps(self):
        """The plan hands the sandbox what acme keeps of a target: the acme push pin (when one
        is kept for the address), ACM's ARN of the first import - none when nothing is."""
        from acmelib.certs import runplan as R
        from acmelib.certs import runtime
        from acmelib import engine as E
        from acmelib.plugins.targets.aws_acm import AwsAcmTarget
        from acmelib.plugins.targets.acme_push import AcmePushTarget

        class Store(object):
            def __init__(self):
                self.meta = {}

            def get_meta(self, k):
                return self.meta.get(k)

            def set_meta(self, k, v):
                self.meta[k] = v
        st = Store()
        url = {'url': 'https://otp.example/admin/'}
        self.assertIsNone(R.push_pin_of(st, AcmePushTarget, url))
        E.push_pin(st, 'https://otp.example/admin/', {'app_id': 'a', 'enc_key': 'k'})
        self.assertEqual(R.push_pin_of(st, AcmePushTarget, url)['app_id'],
                         R.PUSH_PIN['app_id'])
        aws = {'access_key_id': 'AKIAX', 'region': 'eu-central-1'}
        cert = {'name': 'www.example.com', 'names': '["www.example.com"]',
                'key_type': 'rsa-2048'}
        self.assertIsNone(R.kept_of(st, {'kind': 'aws_acm', 'name': 'acm'}, AwsAcmTarget, aws,
                                    {}, cert))
        ctx = runtime.RunContext.__new__(runtime.RunContext)
        ctx.store, ctx.scope = st, 'target:acm'

        class B(object):
            name = 'www.example.com'
            names = ['www.example.com']
            key_type = 'rsa-2048'
        key = AwsAcmTarget(dict(aws), None).kv_arn(B, {})
        ctx.kv_set(key, 'arn:aws:acm:eu-central-1:1:certificate/kept')
        got = R.kept_of(st, {'kind': 'aws_acm', 'name': 'acm'}, AwsAcmTarget, aws, {}, cert)
        self.assertEqual(got, {key: 'arn:aws:acm:eu-central-1:1:certificate/kept'})
        self.assertIsNone(R.kept_of(st, {'kind': 'a10', 'name': 'acm'}, AwsAcmTarget, aws, {},
                                    cert))

    def test_placeholders(self):
        """{EARLIER_PEM} (another certificate of the names) and {CAID} (the chain's CA as a
        module named it) in an answer."""
        from acmelib.certs import plansandbox as P
        from acmelib.certs import pki
        from acmelib.plugins.targets import _common as C
        ca = pki.self_signed(pki.make_key('ec-256'), [], subject={'CN': 'Plan CA'}, days=3,
                             is_ca=True)

        class B(object):
            name = 'www.example.com'
            names = ['www.example.com']
            cert_pem = pki.self_signed(pki.make_key('ec-256'), names, days=3)
            chain_pems = [ca]
        ans = P.Answers([{'body': {'pem': '{EARLIER_PEM}', 'ca': 'acme-ca-{CAID}'}}],
                        [{'command': 'x', 'stdout': '{EARLIER_PEM}'}])
        ans.bundle = B()
        st, hd, raw = ans('GET', 'https://dev/x')
        d = json.loads(raw)
        self.assertIn('BEGIN CERTIFICATE', d['pem'])
        self.assertNotEqual(d['pem'].strip(), B.cert_pem.strip())
        self.assertEqual(d['ca'], 'acme-ca-%s' % C.chain_id(ca))
        self.assertEqual(ans.ssh('x')[1], d['pem'])


class AcmeRecorded(unittest.TestCase):
    """The plain ACME source (issuers/acme.py, 1.0.98): recorded whole against a stand-in of
    the CA at the directory URL it is set to - each request with its JWS decoded (the
    signatures and keys never shown), the answers, the waits, each name's validation put in
    place within it; a renewal after the first issue: ARI asked, the order replaces the
    certificate before, the account kept."""
    HMAC = 'Eab-Hmac-Very-Secret-0123456789abcdefghijklmn'
    CF = ('cloudflare', {'token': 'CfTok3nVerySecret'})
    DAV = ('http_webdav', {'url': 'https://web.example.com', 'user': 'u',
                           'password': 'Dav-Pw-Very-Secret'})

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    def record(self, cfg, names=('www.example.com',), val=None, key_type='ec-256',
               account=None):
        from acmelib.certs import runplan as R
        from acmelib.certs import plansources as PS
        from acmelib.plugins import base
        from acmelib.plugins.issuers import _acme_client as ac
        base.REGISTRY.reload()
        cls = base.REGISTRY.get('issuer', 'acme')
        full = {f['key']: f.get('default') for f in cls.fields or [] if f.get('key')
                and f.get('default') not in (None, '')}
        full.update(cfg)
        sec = R.Secrets()
        scfg, marks = sec.stand_ins(R._fields_of(cls), full)
        ck, ccfg = val or self.CF
        ccls = base.REGISTRY.get('challenge', ck)
        c2, m2 = sec.stand_ins(R._fields_of(ccls), ccfg)
        d = full['directory']
        url = full.get('directory_url') if d == 'custom' else ac.DIRECTORIES[d]
        r = {'id': 'r1', 'family': 'issuer', 'kind': 'acme', 'name': 'ca', 'seconds': 40,
             'op': 'issue', 'config': scfg, 'marks': dict(marks, **m2), 'previous': False,
             'answers': PS.acme_directory_flow(url, d, list(names), profile=cfg.get(
                 'profile'), eab=bool(cfg.get('eab_hmac'))), 'ssh_answers': [],
             'names': list(names),
             'acme': {'account': account, 'preferred': cfg.get('preferred_chain') or '',
                      'profile': cfg.get('profile') or '', 'later': True},
             'challenges': {n: {'kind': ck, 'name': ck, 'config': c2,
                                'answers': R.answers_of(ck, c2, first=False,
                                                        family='challenge'),
                                'ssh_answers': R.ssh_answers_of(ck, c2, family='challenge')}
                            for n in names}}
        got, err = R.record({'runs': [r], 'settings': {}, 'cert': {
            'names': list(names), 'key_type': key_type}}, timeout=150)
        self.assertEqual(err, '')
        run = got['r1']
        self.assertFalse(run.get('error'), run.get('error'))
        self.assertIsNotNone(run.get('later'), run.get('later_error'))
        for evs in (run['events'], run['later']):
            self.assertFalse([e for e in evs if e.get('kind') == 'bypass'])
            self.assertFalse([e.get('url') for e in evs if e.get('fallback')])
        text = R.scrub(run, set(sec.real))
        return run, url, json.dumps(text, ensure_ascii=False)

    @staticmethod
    def calls(evs, host=None):
        return [(e['method'], e['url']) for e in evs if e['kind'] == 'http' and
                (host is None or ('//' + host + '/') in e['url'])]

    def in_order(self, got, want):
        at = 0
        for w in want:
            hit = [i for i in range(at, len(got)) if w in got[i]]
            self.assertTrue(hit, '%s not after %d in %s' % (w, at, got))
            at = hit[0] + 1

    def test_le_dns01_first_issue_and_renewal(self):
        run, url, text = self.record({'directory': 'letsencrypt',
                                      'contacts': ['it@example.com']})
        evs = run['events']
        host = 'acme-v02.api.letsencrypt.org'
        got = ['%s %s' % c for c in self.calls(evs)]
        self.in_order(got, ['GET %s' % url, 'HEAD https://%s/acme/new-nonce' % host,
                            'POST https://%s/acme/new-acct' % host,
                            'POST https://%s/acme/new-order' % host, '/acme/authz/',
                            'POST https://api.cloudflare.com/client/v4/zones/',
                            '/acme/chall/', '/acme/authz/', '/acme/authz/',
                            'DELETE https://api.cloudflare.com/', '/acme/order/',
                            '/acme/finalize/', '/acme/order/', '/acme/order/', '/acme/cert/'])
        # the waits the CA asks for (Retry-After), the validation's phases within
        self.assertEqual([e['seconds'] for e in evs if e['kind'] == 'wait'], [3.0, 2.0])
        self.assertEqual([e['what'] for e in evs if e['kind'] == 'phase'],
                         ['ready', 'cleanup', 'order'])
        said = [e['words'] for e in evs if e['kind'] == 'say']
        self.assertTrue([w for w in said if 'is on every name server' in w], said)
        # the JWS decoded: a new account with its public jwk, then the kid
        acct = [e for e in evs if e['kind'] == 'http' and e['url'].endswith('/new-acct')][0]
        self.assertEqual(acct['body_facts']['format'], 'jws')
        p = acct['body']['protected']
        self.assertEqual((p['alg'], p['url'], p['jwk']['kty']), ('ES256', acct['url'], 'EC'))
        self.assertTrue(p['nonce'])
        self.assertEqual(acct['body']['payload'], {'termsOfServiceAgreed': True,
                                                   'contact': ['mailto:it@example.com']})
        self.assertTrue(acct['body']['signature'].startswith('••••'))
        loc = dict(acct['answered']['headers'])['Location']
        order = [e for e in evs if e['kind'] == 'http' and e['url'].endswith('/new-order')][0]
        self.assertEqual(order['body']['protected']['kid'], loc)
        self.assertNotIn('jwk', order['body']['protected'])
        self.assertEqual(order['body']['payload'], {'identifiers': [
            {'type': 'dns', 'value': 'www.example.com'}]})
        self.assertEqual(dict(order['answered']['headers'])['Location'],
                         [e['url'] for e in evs if e['kind'] == 'http' and
                          '/acme/order/' in e['url']][0])
        fin = [e for e in evs if '/acme/finalize/' in e.get('url', '')][0]
        self.assertIn('certificate request (CSR)', fin['body']['payload']['csr'])
        self.assertEqual(dict(fin['answered']['headers'])['Retry-After'], '2')
        # the renewal: ARI first, the account kept (no new one), the order replaces
        later = run['later']
        lg = ['%s %s' % c for c in self.calls(later)]
        self.in_order(lg, ['GET %s' % url, '/draft-ietf-acme-ari-03/renewalInfo/',
                           'POST https://%s/acme/new-order' % host, '/acme/cert/'])
        self.assertFalse([x for x in lg if x.endswith('/new-acct')])
        o2 = [e for e in later if e['kind'] == 'http' and e['url'].endswith('/new-order')][0]
        ari = [e for e in later if '/renewalInfo/' in e.get('url', '')][0]['url']
        ari = ari.rsplit('/', 1)[1]
        self.assertEqual(o2['body']['payload']['replaces'], ari)
        self.assertEqual(o2['body']['protected']['kid'], loc)
        # as steps: in order, the first issue's and the renewal's own marked
        from acmelib.certs import runplan as R
        steps = R.steps_of(evs, None, later=later)
        words = [s['words'] for s in steps]
        self.in_order(words, ['Reads the CA\'s directory', 'Asks for a nonce',
                              'Makes an ACME account at the CA', 'Orders the certificate',
                              'Reads the authorization of www.example.com: pending',
                              'Until it can be seen', 'Tells the CA to check the proof',
                              'Reads the authorization of www.example.com: valid',
                              'After the CA has looked', 'Back at the CA: the order',
                              'Reads the order: ready', 'Finalizes the order',
                              'Reads the order: processing', 'Waits 2 s',
                              'Reads the order: valid', 'Downloads the certificate'])
        br = {s['words']: s.get('branch') for s in steps}
        self.assertIn('first time', br['Makes an ACME account at the CA'])
        self.assertIn('later renewals', br['Asks the CA when to renew it (ARI, RFC 9773)'])
        self.assertIn('later renewals', br['Orders the certificate for its names, as the '
                                           'renewal of the one before (replaces)'])
        self.assertTrue(all(s['detail'].get('note_jws') for s in steps
                            if (s.get('detail') or {}).get('method') == 'POST' and
                            'letsencrypt' in s['detail']['url']))
        self.assertNotIn('CfTok3nVerySecret', text)
        self.assertNotIn('PRIVATE KEY', text)

    def test_eab_http01_rsa(self):
        """An EAB CA (Google): the account bound with the EAB (its HMAC never shown), HTTP-01
        put in place and checked, an RSA certificate's request, the chain preferred."""
        run, url, text = self.record({'directory': 'google', 'eab_kid': 'kid-123',
                                      'eab_hmac': self.HMAC, 'preferred_chain': 'GTS Root R4'},
                                     names=('www.example.com', 'example.com'), val=self.DAV,
                                     key_type='rsa-2048')
        evs = run['events']
        self.assertEqual(self.calls(evs)[0], ('GET', url))
        acct = [e for e in evs if e['kind'] == 'http' and e['url'].endswith('/new-account')][0]
        self.assertTrue(acct['url'].startswith('https://dv.acme-v02.api.pki.goog/'))
        eab = acct['body']['payload']['externalAccountBinding']
        self.assertEqual(eab['protected'], {'alg': 'HS256', 'kid': 'kid-123',
                                            'url': acct['url']})
        self.assertTrue(eab['signature'].startswith('••••'))
        self.assertNotIn(self.HMAC, text)
        self.assertNotIn('Dav-Pw-Very-Secret', text)
        wire = json.loads(acct['wire']['body'])
        self.assertEqual(wire['signature'], '••••')
        said = [e['words'] for e in evs if e['kind'] == 'say']
        for n in ('www.example.com', 'example.com'):
            self.assertIn('http://%s/.well-known/acme-challenge/PLAN-TOKEN-from-the-CA-'
                          '0000000000 answers with the right value' % n, said)
        # the alternate chain fetched (Link: rel="alternate") and taken: no warning
        certs = [e['url'] for e in evs if e['kind'] == 'http' and '/certificate/' in e['url']]
        self.assertEqual(len(certs), 2)
        self.assertFalse([w for w in said if 'no chain of the CA ends at' in w], said)
        self.assertTrue([w for w in said if w.startswith('the certificate came')])
        # the request is for the certificate's own key type
        fin = [e for e in evs if e['kind'] == 'http' and e['url'].endswith('/finalize')][0]
        self.assertIn('CSR', fin['body']['payload']['csr'])
        import re
        self.assertTrue(int(re.search(r'(\d+) B', fin['body']['payload']['csr']).group(1)) > 500)

    def test_account_made_before_and_other_directories(self):
        """An account made before is used as it is (its kid, no new account); every preset
        is asked at its own directory URL, its requests on that CA's host."""
        acct = 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/99887766'
        run, url, _t = self.record({'directory': 'letsencrypt-staging'}, account=acct)
        evs = run['events']
        self.assertFalse([e for e in evs if e['kind'] == 'http' and '/new-acct' in e['url']])
        order = [e for e in evs if e['kind'] == 'http' and e['url'].endswith('/new-order')][0]
        self.assertEqual(order['body']['protected']['kid'], acct)
        import urllib.parse
        for cfg in ({'directory': 'zerossl', 'contacts': ['it@example.com']},
                    {'directory': 'buypass'},
                    {'directory': 'sslcom-ecc', 'eab_kid': 'k1', 'eab_hmac': self.HMAC},
                    {'directory': 'digicert', 'eab_kid': 'k1', 'eab_hmac': self.HMAC},
                    {'directory': 'custom', 'directory_url':
                     'https://ca.example.local/acme/acme/directory', 'profile': 'tls'}):
            run, url, text = self.record(cfg, names=('*.example.com',))
            host = urllib.parse.urlsplit(url).hostname
            got = self.calls(run['events'])
            self.assertEqual(got[0], ('GET', url), cfg)
            ca = [u for _m, u in got if 'cloudflare' not in u and 'zerossl.com/acme/eab' not in u]
            self.assertTrue(all(urllib.parse.urlsplit(u).hostname == host for u in ca),
                            (cfg, ca))
            self.assertTrue([u for _m, u in got if u.endswith('dns01')], cfg)
            self.assertNotIn(self.HMAC, text)
            if cfg['directory'] == 'zerossl':
                self.assertIn(('POST', 'https://api.zerossl.com/acme/eab-credentials-email'),
                              got)
            if cfg['directory'] == 'custom':
                o = [e for e in run['events'] if e['kind'] == 'http' and
                     e['url'].endswith('/new-order')][0]
                self.assertEqual(o['body']['payload']['profile'], 'tls')
            # ARI where acme says the CA has it (DigiCert here): the module's own decision
            # from the directory - renewalInfo asked and replaces sent, else neither
            o2 = [e for e in run['later'] if e['kind'] == 'http' and
                  e['url'].endswith('/new-order')][0]
            ari = cfg['directory'] == 'digicert'
            self.assertEqual('replaces' in o2['body']['payload'], ari, cfg)
            self.assertEqual(bool([e for e in run['later'] if e['kind'] == 'http' and
                                   'renewal-info' in e['url']]), ari, cfg)
            self.assertEqual(bool([e for e in run['later'] if e.get('what') == 'no-ari']),
                             not ari, cfg)

    def test_presets_as_acme_says(self):
        """The stand-in directories offer what acme itself says of each CA: EAB where the
        source's option says "(EAB", ARI at Let's Encrypt and DigiCert, Let's Encrypt's
        profiles as the "ACME profile" help names them."""
        from acmelib.certs import plansources as PS
        from acmelib.plugins.issuers import _acme_client as ac
        eab = PS.acme_eab_presets()
        self.assertIn('digicert', eab)
        self.assertNotIn('letsencrypt', eab)
        self.assertNotIn('buypass', eab)
        for d, url in ac.DIRECTORIES.items():
            rules = PS.acme_directory_flow(url, d, ['www.example.com'])
            dr = rules[0]['body']
            self.assertEqual(bool(dr['meta'].get('externalAccountRequired')), d in eab, d)
            self.assertEqual('renewalInfo' in dr, d in PS.ACME_ARI, d)
            self.assertEqual(sorted(dr['meta'].get('profiles') or []), sorted(
                ['classic', 'tlsserver', 'shortlived'] if d.startswith('letsencrypt') else []),
                d)

    def test_chain_taken_said(self):
        """Where a chain is preferred, a step says which the module took and where it ends."""
        from acmelib.certs import runplan as R
        run, _u, _t = self.record({'directory': 'letsencrypt',
                                   'preferred_chain': 'ISRG Root X2'})
        steps = R.steps_of(run['events'], None, later=run['later'])
        got = [s['words'] for s in steps if s['words'].startswith('The chain taken')]
        self.assertEqual(got, ['The chain taken: the preferred chain ISRG Root X2 (it ends at '
                               'ISRG Root X2)'])
        st = R.steps_of([{'kind': 'chain', 'preferred': 'X', 'top': 'Y', 'where': 'default'}])
        self.assertEqual(st[0]['words'], 'The chain taken: the default chain - X not offered '
                                         '(it ends at Y)')
        run, _u, _t = self.record({'directory': 'letsencrypt'})
        self.assertFalse([e for e in run['events'] if e['kind'] == 'chain'])

    def test_not_recorded_falls_back(self):
        """A recording that failed: the description, said so - never a broken phase."""
        from acmelib.certs import runplan as R
        described = [{'kind': 'read', 'words': 'Reads the CA\'s directory'}]
        for res in (None, {'events': [], 'error': 'this CA needs External Account Binding'},
                    {'events': [{'kind': 'bypass', 'how': 'socket', 'what': 'x'}]}):
            steps, ok = R.acme_recorded(described, res, {}, False, False)
            self.assertFalse(ok)
            self.assertIn('could not be recorded', steps[0]['words'])
            self.assertEqual(steps[1:], described)
        steps, ok = R.acme_recorded(described, {'events': [
            {'kind': 'http', 'method': 'GET', 'url': 'https://ca/directory'}]}, {}, False, False)
        self.assertTrue(ok)
        self.assertIn('A renewal could not be recorded', steps[1]['words'])


HOG = r"""
import os
import sys
from acmelib.plugins.base import Target


class Hog(Target):
    kind = 'planhog'
    label = 'A module that misbehaves'
    fields = []

    def deploy(self, bundle, options):
        what = (options or {}).get('what')
        if what == 'print':
            print('hello from the module')
            sys.stderr.write('and its stderr\n')
            os.write(1, b'straight to the file of stdout\n')
            return 'ok'
        if what == 'mem':
            keep = []
            for _i in range(40):
                keep.append(bytearray(100 * 1024 * 1024))
            return 'ok %d' % len(keep)
        if what == 'threads':
            import threading
            go = threading.Event()
            got = []

            def work():
                got.append([bytearray(4096) for _ in range(64)])
                go.wait(10)
            ts = [threading.Thread(target=work) for _ in range(32)]
            for t in ts:
                t.start()
            go.set()
            for t in ts:
                t.join()
            return 'ok %d threads' % len(got)
        if what == 'stdout':
            while True:
                sys.stdout.write('x' * 65536)
                os.write(1, b'y' * 65536)
        if what == 'loop':
            while True:
                pass
        return 'ok'
"""


class SandboxLimits(unittest.TestCase):
    """The recording's process kept in bounds (1.0.101): a module's print() is no longer the
    recording's answer (one lost the whole plan) - it is kept aside, capped, and shown with the
    debug details; its memory is limited; one writing to stdout in a loop no longer fills the
    daemon's memory; one that loops is stopped."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from acmelib.plugins import base
        cls.base = base
        cls.dir = tempfile.mkdtemp(prefix='acme-plan-hog-')
        os.makedirs(os.path.join(cls.dir, 'targets'))
        with open(os.path.join(cls.dir, 'targets', 'planhog.py'), 'w') as f:
            f.write(HOG)
        cls.dirs = list(base.REGISTRY.dirs)
        base.REGISTRY.dirs = base.REGISTRY.dirs[:1] + [cls.dir]
        base.REGISTRY.reload()

    @classmethod
    def tearDownClass(cls):
        import shutil
        cls.base.REGISTRY.dirs = cls.dirs
        cls.base.REGISTRY.reload()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def record(self, what, seconds=4, timeout=60):
        from acmelib.certs import runplan as R
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'planhog', 'name': 'h', 'op': 'deploy',
            'config': {}, 'options': {'what': what}, 'seconds': seconds, 'answers': [],
            'ssh_answers': []}], 'cert': {'names': ['www.example.com'], 'key_type': 'ec-256'}},
            timeout=timeout)
        self.assertEqual(err, '')
        return got['r1']

    def test_print_kept_aside(self):
        from acmelib.certs import runplan as R
        run = self.record('print')
        self.assertIsNone(run['error'])
        self.assertEqual(run['said'], 'ok')
        out = [e for e in run['events'] if e['kind'] == 'output']
        self.assertEqual(len(out), 1)
        self.assertIn('hello from the module', out[0]['text'])
        self.assertIn('and its stderr', out[0]['text'])
        self.assertNotIn('straight to the file', out[0]['text'])     # that went nowhere
        steps = R.steps_of(run['events'])
        st = [x for x in steps if x.get('words', '').startswith('What the module printed')]
        self.assertEqual(len(st), 1)
        self.assertTrue(st[0]['debug'])

    def test_stdout_flood(self):
        import resource
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        run = self.record('stdout', seconds=2)
        self.assertIn('took too long', run['error'])
        out = [e for e in run['events'] if e['kind'] == 'output'][0]
        self.assertLessEqual(len(out['text']), 4000)
        self.assertGreater(out['over'], 0)
        grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        self.assertLess(grown, 200 * 1024, 'the test process grew by %d kB' % grown)

    def test_memory_capped(self):
        with unittest.mock.patch.dict(os.environ, {'ACME_PLAN_MEM_MB': '512'}):
            run = self.record('mem', seconds=20)
        self.assertIn('MemoryError', run['error'] or '')
        self.assertIsNone(run['said'])

    def test_threads_run(self):
        """A module starting threads (an SDK's transfers) runs: the limit is of the memory it
        writes, not of its address space (RLIMIT_AS stopped it at about 13 threads)."""
        run = self.record('threads', seconds=20)
        self.assertIsNone(run['error'])
        self.assertEqual(run['said'], 'ok 32 threads')

    def test_loop_stopped(self):
        run = self.record('loop', seconds=2)
        self.assertIn('it was stopped after 2 s', run['error'])

    def test_output_read_with_a_cap(self):
        """What the daemon reads of the process at most: beyond it, the process is stopped."""
        import time
        from acmelib.certs import runplan as R
        t0 = time.monotonic()
        rc, out, err, why = R.run_capped(
            [sys.executable, '-c', 'import os\nwhile True: os.write(1, b"z" * 65536)'],
            b'', 60, cap=1 << 20)
        self.assertEqual(why, 'size')
        self.assertLessEqual(len(out), 1 << 20)
        self.assertNotEqual(rc, 0)
        self.assertLess(time.monotonic() - t0, 30)
        rc, out, err, why = R.run_capped(
            [sys.executable, '-c', 'import sys, time; sys.stdout.write(sys.stdin.read()); '
             'sys.stderr.write("e" * 200000); time.sleep(0.2)'], b'echo', 60, err_cap=1000)
        self.assertEqual((rc, out, why, len(err)), (0, b'echo', '', 1000))
        rc, out, err, why = R.run_capped([sys.executable, '-c', 'import time; time.sleep(30)'],
                                         b'', 1)
        self.assertEqual(why, 'time')


if __name__ == '__main__':
    unittest.main(verbosity=2)
