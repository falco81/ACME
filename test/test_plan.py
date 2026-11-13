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
        self.assertEqual(cmds[-1], 'write memory')
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
        self.in_order(evs, 'SAY what bmc serves cannot be read',
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
