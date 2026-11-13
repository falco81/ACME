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
        wg = json.dumps(groups['wg']['per_name'], ensure_ascii=False)
        self.assertIn('http://127.0.0.1:%d/auth/login' % self.listener.port, wg)
        self.assertIn('_acme-challenge', wg)
        self.assertIn('computed at the time from the token', wg)
        cf = json.dumps(groups['cf']['per_name'], ensure_ascii=False)
        self.assertIn('/zones/zone123/dns_records', cf)
        self.assertNotIn(SECRETS['cf'], cf)
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
        self.assertIn('iLO', json.dumps(ilo[:2]))
        self.assertEqual(ilo[-1]['url'], R.ANSWERS['redfish'][0]['url'])
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
        self.assertEqual([m for m, u in calls], ['GET', 'GET', 'PUT', 'GET'])
        self.assertTrue(calls[2][1].endswith('/ssl-certificate'), calls)
        self.assertIn('/config/tasks/', calls[3][1])


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
        self.assertEqual(cmds[-1], 'write memory')
        self.assertFalse([e for e in evs if e['kind'] == 'wait'])
        evs = self.record('netapp_ontap', {'host': 'c1', 'user': 'u', 'password': 'p'},
                          {'svm': 'vs-prod'}, version='9.10')
        calls = [(e['method'], e['url'].split('/api/', 1)[1].split('?')[0]) for e in evs
                 if e['kind'] == 'http']
        self.assertIn(('POST', 'security/certificates'), calls)
        self.assertEqual(calls[-2][0], 'PATCH')
        self.assertFalse([e for e in evs if e['kind'] == 'wait'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
