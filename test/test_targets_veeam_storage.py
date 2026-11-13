#!/usr/bin/env python3
"""The Veeam and storage / HCI targets (1.0.95), without a network and without a device.

    python3 test/test_targets_veeam_storage.py

    netapp_ontap         ''  9.6  9.10   ONTAP REST: install, bind (web / certificate field)
    pure_flasharray      ''               REST 2.x: login with the API token, PATCH in place
    pure_flashblade      ''               the same, /api/login and "private_key"
    qnap                 ''               SSH: /etc/stunnel/stunnel.pem + uca.pem, stunnel
    cockpit              ''               SSH: ws-certs.d, cockpit-certificate-ensure, sudo
    veeam_vbr            ''  12.3  13     PowerShell over SSH: Add-VBRBackupServerCertificate
    veeam_cloud_connect  ''               Add-VBRCloudGatewayCertificate
    veeam_vb365          ''               Set-VBORestAPISettings / Set-VBOSecuritySettings...
    nutanix              7.5              v4.4, X-ntnx-api-key, the key types of AOS 7.x

The fake Context, SSH session and certificates are those of test_targets.py; the requests
are checked against what the vendor guides (navody/certifikaty, 2026-11) document.
"""
import base64
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx, openssl  # noqa: E402
from acmelib.plugins.base import PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import veeam_vbr as VBR  # noqa: E402
from acmelib.plugins.targets import netapp_ontap as ONTAP  # noqa: E402

ROOT = os.path.dirname(HERE)
GUIDES = os.path.join(ROOT, 'acmelib', 'plugins', 'guides', 'targets')
KINDS = {'netapp_ontap': ['', '9.10', '9.6'], 'pure_flasharray': [''],
         'pure_flashblade': [''], 'qnap': [''], 'cockpit': [''],
         'veeam_vbr': ['', '12.3', '13'], 'veeam_cloud_connect': [''], 'veeam_vb365': ['']}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, version, config, ctx):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (kind, cls.module_version, version)
    return cls(config, ctx)


def script_of(cmd, ssh=None):
    """The PowerShell a command ran: -EncodedCommand, or the .ps1 uploaded for -File."""
    if '-EncodedCommand ' in cmd:
        return base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le')
    m = re.search(r'-File "([^"]+)"', cmd)
    if m and ssh is not None:
        for path, data, _mode in ssh.puts:
            if path == m.group(1):
                return data.decode('utf-8-sig')
    return ''


# ---------------------------------------------------------------------------
class RegistryTest(unittest.TestCase):
    def test_kinds_versions_fields(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        for kind, vers in KINDS.items():
            got = reg.versions_of('target', kind)
            self.assertEqual(sorted(got), sorted(vers), kind)
            self.assertIs(reg.get('target', kind), got[''], 'the plain one is the default')
            for v, cls in got.items():
                d = cls.describe()
                json.dumps(d)
                self.assertTrue(d['title'] and d['vendor'] and d['description'], kind)
                self.assertEqual(d['doc'], 'targets.md', kind)
                if v:
                    self.assertIn(cls.version_label, cls.description, (kind, v))
                    self.assertEqual(cls.fields, got[''].fields, 'saved settings fit')
                    self.assertEqual(cls.deploy_fields, got[''].deploy_fields)
                keys = [f['key'] for f in d['fields']]
                for f in d['fields'] + d['deploy_fields']:
                    self.assertIn(f['type'], FIELD_TYPES, (kind, f['key']))
                    if f['key'] in ('token', 'password', 'api_token', 'api_key'):
                        self.assertEqual(f['type'], 'secret', (kind, f['key']))
                for f in d['deploy_fields']:
                    self.assertNotIn(f['key'], keys, (kind, f['key']))
                with open(cls._module_file, encoding='utf-8') as fh:
                    src = fh.read()
                doc = src.split('"""')[1]
                self.assertIn('https://', doc, kind)
                self.assertIn('Less certain', doc, kind)
            if len(vers) > 1:
                labels = {k: c.version_label for k, c in got.items()}
                self.assertEqual(labels[''], 'any version (detects it)')

    def test_nutanix_version_added_plain_kept(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'nutanix')
        self.assertEqual(sorted(vers), ['', '7.5'])
        self.assertIs(reg.get('target', 'nutanix'), vers[''])
        self.assertEqual(vers[''].__module__.rsplit('.', 1)[-1], 'nutanix')
        self.assertIn(vers['7.5'].version_label, vers['7.5'].description)

    def test_existing_kinds_have_no_duplicate_versions(self):
        """synology, proxmox, proxmox_backup, kubernetes: their documented versions are the
        same calls - no version added (the user asked for no duplicates)."""
        reg = Registry(extra_dirs=[]).reload()
        for kind in ('synology', 'proxmox', 'proxmox_backup', 'kubernetes', 'windows_ssh',
                     'ssh'):
            self.assertEqual(sorted(reg.versions_of('target', kind)), [''], kind)


# ---------------------------------------------------------------------------
# NetApp ONTAP
# ---------------------------------------------------------------------------
class Ontap(object):
    """An ONTAP cluster answering as its REST reference documents."""
    def __init__(self, version=(9, 16, 1), certs=None, bound='old-uuid', post=202,
                 patch_drops=False):
        self.version = version
        self.certs = list(certs or [])         # [{'uuid', 'name', 'svm'}]
        self.bound = {'': bound, 'svm1': 'svm-old'}
        self.post = post
        self.patch_drops = patch_drops
        self.jobs = 0

    def routes(self):
        return [
            ('GET', r'/api/cluster\?fields=version', self.cluster),
            ('GET', r'/api/cluster/jobs/', self.job),
            ('GET', r'/api/svm/svms\?name=svm1', (200, {'records': [{'uuid': 'svm1-uuid',
                                                                   'name': 'svm1'}]})),
            ('GET', r'/api/svm/svms\?name=', (200, {'records': []})),
            ('GET', r'/api/security/certificates\?', self.list),
            ('POST', r'/api/security/certificates\?return_timeout=120', self.install),
            ('PATCH', r'/api/cluster/web$', self.bind('', True)),
            ('PATCH', r'/api/svm/svms/svm1-uuid/web$', self.bind('svm1', True)),
            ('PATCH', r'/api/cluster$', self.bind('', False)),
            ('PATCH', r'/api/svm/svms/svm1-uuid$', self.bind('svm1', False)),
            ('GET', r'/api/cluster/web\?fields=certificate',
             lambda c: (200, {'certificate': {'uuid': self.bound['']}})),
            ('GET', r'/api/cluster\?fields=certificate',
             lambda c: (200, {'certificate': {'uuid': self.bound['']}})),
            ('GET', r'/api/svm/svms/svm1-uuid(/web)?\?fields=certificate',
             lambda c: (200, {'certificate': {'uuid': self.bound['svm1']}})),
            ('DELETE', r'/api/security/certificates/', (200, {})),
        ]

    def cluster(self, call):
        g, ma, mi = self.version
        return 200, {'name': 'cluster1', 'version': {'full': 'NetApp Release %d.%d.%d' % (
            g, ma, mi), 'generation': g, 'major': ma, 'minor': mi}}

    def job(self, call):
        self.jobs += 1
        return 200, {'state': 'running' if self.jobs < 2 else 'success'}

    def list(self, call):
        q = call['query']
        recs = [c for c in self.certs if (not q.get('name') or c['name'] == q['name'][0]) and
                (c.get('svm', '') == (q.get('svm.name') or [''])[0])]
        return 200, {'records': recs, 'num_records': len(recs)}

    def install(self, call):
        body = json.loads(call['body'])
        self.certs.append({'uuid': 'new-uuid', 'name': body['name'],
                           'svm': (body.get('svm') or {}).get('name', '')})
        if self.post == 202:
            return 202, {'job': {'uuid': 'job-1'}}
        return 201, {}

    def bind(self, svm, web):
        def f(call):
            if web and self.version < (9, 10, 0):
                return 404, {'error': {'message': 'API not found', 'code': '3'}}
            self.bound[svm] = json.loads(call['body'])['certificate']['uuid']
            if self.patch_drops:
                raise ConnectionResetError('the web services restart')
            return 200, {}
        return f


class FailingHttpCtx(FakeCtx):
    """A FakeCtx whose canned answers may raise (a dropped connection)."""
    def http(self, *a, **k):
        try:
            return FakeCtx.http(self, *a, **k)
        except ConnectionResetError as e:
            raise PluginError('https://cluster1 cannot be reached: %s' % e)


class OntapTest(unittest.TestCase):
    CONF = {'host': 'cluster1', 'user': 'svc_cert', 'password': 'pw'}

    def run_deploy(self, version, ontap, options=None):
        b = FakeBundle()
        ctx = FailingHttpCtx(ontap.routes())
        t = make('netapp_ontap', version, dict(self.CONF), ctx)
        t._sleep = lambda s: None
        words = t.deploy(b, dict(options or {}))
        return ctx, words, b

    def check_install(self, ctx, b, svm=None):
        post = ctx.find('POST', r'/api/security/certificates')
        self.assertEqual(len(post), 1)
        body = ctx.json(post[0])
        self.assertEqual(body['type'], 'server')
        self.assertEqual(body['name'], C.object_name(b, {}))
        self.assertEqual(body['public_certificate'], b.cert_pem)
        self.assertEqual(body['private_key'], b.key_pem)
        self.assertEqual(body['intermediate_certificates'], C.chain_list(b))
        self.assertEqual(body.get('svm'), {'name': svm} if svm else None)
        auth = post[0]['headers']['Authorization']
        self.assertEqual(base64.b64decode(auth.split()[1]).decode(), 'svc_cert:pw')

    def test_910_web_endpoints(self):
        for version in ('', '9.10'):
            o = Ontap((9, 16, 1))
            ctx, words, b = self.run_deploy(version, o)
            self.check_install(ctx, b)
            p = ctx.find('PATCH', r'/api/cluster/web$')
            self.assertEqual([ctx.json(c) for c in p], [{'certificate': {'uuid': 'new-uuid'}}])
            self.assertFalse(ctx.find('PATCH', r'/api/cluster$'), 'not the deprecated field')
            self.assertEqual(len(ctx.find('GET', r'/api/cluster/jobs/job-1')), 2, 'job waited')
            self.assertIn('bound to the cluster', words)

    def test_910_svm(self):
        o = Ontap((9, 18, 1))
        ctx, words, b = self.run_deploy('9.10', o, {'svm': 'svm1'})
        self.check_install(ctx, b, 'svm1')
        self.assertEqual([ctx.json(c) for c in ctx.find('PATCH', r'/svm/svms/svm1-uuid/web$')],
                         [{'certificate': {'uuid': 'new-uuid'}}])
        self.assertEqual(make('netapp_ontap', '9.10', self.CONF, ctx).served_places(
            {'svm': 'svm1'}), [])

    def test_96_certificate_field(self):
        for version in ('', '9.6'):
            o = Ontap((9, 8, 0), post=201)
            ctx, words, b = self.run_deploy(version, o)
            self.check_install(ctx, b)
            self.assertEqual([ctx.json(c) for c in ctx.find('PATCH', r'/api/cluster$')],
                             [{'certificate': {'uuid': 'new-uuid'}}])
            self.assertFalse(ctx.find('PATCH', r'/web$'))
        o = Ontap((9, 9, 1), post=201)
        ctx, words, b = self.run_deploy('9.6', o, {'svm': 'svm1'})
        self.assertEqual(len(ctx.find('PATCH', r'/api/svm/svms/svm1-uuid$')), 1)

    def test_refused_before_any_change(self):
        for version, ver, fit in (('9.6', (9, 12, 1), 'ONTAP 9.10.1 - 9.19'),
                                  ('9.10', (9, 8, 0), 'ONTAP 9.6 - 9.9'),
                                  ('9.10', (9, 5, 0), 'any version (detects it)')):
            o = Ontap(ver)
            ctx = FailingHttpCtx(o.routes())
            with self.assertRaises(PluginError) as e:
                make('netapp_ontap', version, self.CONF, ctx).deploy(FakeBundle(), {})
            self.assertFalse(e.exception.retry)
            self.assertIn('"%s"' % fit, str(e.exception))
            self.assertEqual({c['method'] for c in ctx.calls}, {'GET'}, 'nothing changed')
        with self.assertRaises(PluginError):
            make('netapp_ontap', '9.6', self.CONF, FailingHttpCtx(Ontap((9, 16, 1)).routes())).test()
        self.assertIn('9.16.1', make('netapp_ontap', '9.10', self.CONF,
                                     FailingHttpCtx(Ontap((9, 16, 1)).routes())).test())
        self.assertEqual(ONTAP.version_for((9, 19, 1))[0], '9.10')
        self.assertEqual(ONTAP.version_for((9, 7, 0))[0], '9.6')

    def test_newer_warned(self):
        o = Ontap((9, 21, 1))
        ctx, words, b = self.run_deploy('9.10', o)
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])

    def test_same_twice_noop_and_cleanup(self):
        b = FakeBundle()
        prefix = C.name_prefix(b, {})
        olds = [{'uuid': 'u%d' % i, 'name': prefix + '2025%02d01-0000000%d' % (i, i), 'svm': ''}
                for i in range(1, 4)]
        o = Ontap((9, 16, 1), certs=olds)
        ctx = FailingHttpCtx(o.routes())
        t = make('netapp_ontap', '9.10', self.CONF, ctx)
        t._sleep = lambda s: None
        t.deploy(b, {'keep': 1})
        dels = sorted(c['path'] for c in ctx.find('DELETE', r'/certificates/'))
        self.assertEqual(dels, ['/api/security/certificates/u1', '/api/security/certificates/u2'])
        n = len(ctx.calls)
        self.assertIn('unchanged', t.deploy(b, {'keep': 1}))
        self.assertFalse([c for c in ctx.calls[n:] if c['method'] != 'GET'])

    def test_dropped_connection_on_bind_checked(self):
        o = Ontap((9, 16, 1), patch_drops=True)
        ctx, words, b = self.run_deploy('9.10', o)
        self.assertTrue([w for lvl, w in ctx.steps if 'connection dropped' in w])
        self.assertTrue(ctx.find('GET', r'/api/cluster/web\?fields=certificate'))

    def test_errors_in_words(self):
        o = Ontap((9, 16, 1))
        routes = [('POST', r'/api/security/certificates', (400, {'error': {
            'message': 'Failed to read the X509 from BIO', 'code': '3735645'}}))] + o.routes()
        with self.assertRaises(PluginError) as e:
            make('netapp_ontap', '', self.CONF, FailingHttpCtx(routes)).deploy(FakeBundle(), {})
        self.assertIn('Failed to read the X509 from BIO', str(e.exception))
        self.assertNotIn('PRIVATE KEY', e.exception.detail or '')
        with self.assertRaises(PluginError) as e:
            make('netapp_ontap', '', self.CONF, FakeCtx([
                ('GET', r'/api/cluster', (401, {'error': {'message': 'not authorized'}}))])).test()
        self.assertIn('401', str(e.exception))

    def test_unknown_svm(self):
        with self.assertRaises(PluginError) as e:
            self.run_deploy('', Ontap(), {'svm': 'nope'})
        self.assertIn('no SVM named "nope"', str(e.exception))


# ---------------------------------------------------------------------------
# Pure Storage
# ---------------------------------------------------------------------------
class PureTest(unittest.TestCase):
    def routes(self, have_pem='', fb=False):
        login = r'/api/login$' if fb else r'/api/2\.59/login$'
        return [
            ('GET', r'/api/api_version$', (200, {'version': ['1.0', '1.19', '2.0', '2.9',
                                                             '2.59']})),
            ('POST', login, lambda c: (200, {}, {'X-Auth-Token': 'SESSION'})
             if c['headers'].get('api-token') == 'TKN' else (401, {'message': 'bad'})),
            ('GET', r'/api/2\.59/certificates\?names=', (200, {'items': [{
                'name': 'management', 'certificate': have_pem, 'common_name': 'array01',
                'status': 'self-signed'}]})),
            ('PATCH', r'/api/2\.59/certificates\?names=', (200, {'items': [{}]})),
            ('POST', r'/api/2\.59/logout$', (200, {})),
        ]

    def test_flasharray(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        t = make('pure_flasharray', '', {'host': 'array01', 'api_token': 'TKN'}, ctx)
        self.assertIn('replaced management', t.deploy(b, {}))
        p = ctx.find('PATCH', r'certificates\?names=management$')
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]['headers']['x-auth-token'], 'SESSION')
        body = ctx.json(p[0])
        self.assertEqual(body, {'certificate': b.cert_pem, 'key': b.key_pem,
                                'intermediate_certificate': b.chain_pems[0].strip() + '\n'})
        self.assertEqual(len(ctx.find('POST', r'/logout$')), 1, 'signed out')
        self.assertNotIn('api-token', ctx.find('GET', r'/api/api_version')[0]['headers'])
        self.assertEqual(t.served_places({}), [('array01', 443)])
        self.assertEqual(t.served_places({'cert_name': 'vasa-ct0'}), [])

    def test_same_noop_and_bad_name(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes(have_pem=b.cert_pem))
        t = make('pure_flasharray', '', {'host': 'array01', 'api_token': 'TKN'}, ctx)
        self.assertIn('unchanged', t.deploy(b, {}))
        self.assertFalse(ctx.find('PATCH', r'.'))
        self.assertEqual(len(ctx.find('POST', r'/logout$')), 1)
        with self.assertRaises(PluginError):
            t.deploy(b, {'cert_name': 'x;y'})
        t.deploy(b, {'force': True})
        self.assertEqual(len(ctx.find('PATCH', r'.')), 1, 'force does it again')

    def test_flashblade_private_key_and_login(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes(fb=True))
        t = make('pure_flashblade', '', {'host': 'fb01', 'api_token': 'TKN'}, ctx)
        t.deploy(b, {'cert_name': 'global'})
        body = ctx.json(ctx.find('PATCH', r'names=global$')[0])
        self.assertEqual(body['private_key'], b.key_pem)
        self.assertNotIn('key', body)
        self.assertTrue(ctx.find('POST', r'/api/login$'))

    def test_api_version_by_hand_and_bad_token(self):
        ctx = FakeCtx(self.routes())
        t = make('pure_flasharray', '', {'host': 'a', 'api_token': 'TKN', 'api_version': '2.59'},
                 ctx)
        self.assertIn('REST API 2.59', t.test())
        self.assertFalse(ctx.find('GET', r'api_version'))
        with self.assertRaises(PluginError) as e:
            make('pure_flasharray', '', {'host': 'a', 'api_token': 'nope'},
                 FakeCtx(self.routes())).test()
        self.assertIn('401', str(e.exception))
        with self.assertRaises(PluginError):
            make('pure_flasharray', '', {'host': 'a', 'api_token': 'TKN', 'api_version': '1.19'},
                 FakeCtx(self.routes())).test()


# ---------------------------------------------------------------------------
# QNAP
# ---------------------------------------------------------------------------
class QnapTest(unittest.TestCase):
    CONF = {'host': 'nas01', 'user': 'admin', 'auth': 'password', 'password': 'pw'}

    def test_writes_restarts_then_noop(self):
        b = FakeBundle()
        ssh = FakeSsh([(r'BEGIN CERTIFICATE', (0, '', ''))])
        ctx = FakeCtx(ssh=ssh)
        t = make('qnap', '', self.CONF, ctx)
        self.assertIn('stunnel restarted', t.deploy(b, {}))
        puts = {p.rsplit('.', 1)[1]: d for p, d, _m in ssh.puts}
        self.assertEqual(puts['pem'], (b.key_pem + b.cert_pem).encode())
        self.assertEqual(puts['uca'], b.chain_pems[0].encode())
        cmds = '\n'.join(c for c, _i in ssh.runs)
        self.assertIn('cp -p /etc/stunnel/stunnel.pem /etc/stunnel/stunnel.pem.acme-prev', cmds)
        self.assertIn('> /etc/stunnel/stunnel.pem', cmds)
        self.assertIn('> /etc/stunnel/uca.pem', cmds)
        self.assertIn('/etc/init.d/stunnel.sh restart', cmds)
        self.assertNotIn('Qthttpd', cmds)
        # the NAS now shows it: nothing done
        ssh.answers = [(r'BEGIN CERTIFICATE', (0, b.cert_pem, ''))]
        n = len(ssh.runs)
        self.assertIn('unchanged', t.deploy(b, {}))
        self.assertEqual(len(ssh.runs), n + 1)
        self.assertEqual(t.served_places({}), [('nas01', 443)])

    def test_restart_fails_put_back(self):
        ssh = FakeSsh([(r'^sh -c .*stunnel\.sh restart\'?$', (1, '', 'stunnel: bad key')),
                       (r"sed -n", (0, '', ''))])
        ctx = FakeCtx(ssh=ssh)
        with self.assertRaises(PluginError) as e:
            make('qnap', '', self.CONF, ctx).deploy(FakeBundle(), {'restart_web': True})
        self.assertIn('previous certificate is back', str(e.exception))
        cmds = '\n'.join(c for c, _i in ssh.runs)
        self.assertIn('cp -p /etc/stunnel/stunnel.pem.acme-prev /etc/stunnel/stunnel.pem', cmds)
        self.assertNotIn('Qthttpd', cmds)

    def test_test_says_when_not_qnap(self):
        t = make('qnap', '', self.CONF, FakeCtx(ssh=FakeSsh([(r'id -un', (0, 'admin\n', ''))])))
        with self.assertRaises(PluginError):
            t.test()
        t = make('qnap', '', self.CONF, FakeCtx(ssh=FakeSsh([(r'id -un', (0, 'admin\nSTUNNEL\n',
                                                                          ''))])))
        self.assertIn('stunnel.pem is there', t.test())


# ---------------------------------------------------------------------------
# Cockpit
# ---------------------------------------------------------------------------
class CockpitTest(unittest.TestCase):
    CONF = {'host': 'srv01', 'user': 'svc-cert', 'auth': 'password', 'password': 'pw',
            'sudo': True}

    def world(self, ensure_says=None, ensure_rc=0, files='0-self-signed.cert\n'):
        b = FakeBundle()
        base = '90-' + C.object_name(b, {})
        said = ensure_says if ensure_says is not None else \
            'Using certificate /etc/cockpit/ws-certs.d/%s.crt\n' % base
        return b, base, FakeSsh([
            (r'^ls -1 /etc/cockpit/ws-certs.d$', (0, files, '')),
            (r'test -x /usr/libexec/cockpit-certificate-ensure',
             (0, '/usr/libexec/cockpit-certificate-ensure\n', '')),
            (r'cockpit-certificate-ensure --check', (ensure_rc, said, '')),
            (r'test -d /etc/pki/ca-trust/source/anchors', (0, '/etc/pki/ca-trust/source/anchors\n',
                                                           '')),
        ])

    def test_deploy_with_sudo_each_command(self):
        old = '90-%s20250101-00000001' % C.name_prefix(FakeBundle(), {})
        b, base, ssh = self.world(files='0-self-signed.cert\n%s.crt\n%s.key\n' % (old, old))
        t = make('cockpit', '', self.CONF, FakeCtx(ssh=ssh))
        t.deploy(b, {'trust_ca': True, 'keep': 0})
        cmds = [c for c, _i in ssh.runs]
        d = '/etc/cockpit/ws-certs.d/'
        self.assertIn('sudo -n install -m 0644 -o root -g root %s %s%s.crt'
                      % (ssh.puts[0][0], d, base), cmds)
        self.assertIn('sudo -n install -m 0600 -o root -g root %s %s%s.key'
                      % (ssh.puts[1][0], d, base), cmds)
        self.assertEqual(ssh.puts[0][1], b.fullchain_pem.encode())
        self.assertEqual(ssh.puts[1][1], b.key_pem.encode())
        self.assertIn('sudo -n /usr/libexec/cockpit-certificate-ensure --check', cmds)
        self.assertIn('sudo -n /usr/bin/update-ca-trust extract', cmds)
        self.assertIn('sudo -n systemctl restart cockpit.service', cmds)
        self.assertIn('sudo -n rm -f %s%s.crt %s%s.key' % (d, old, d, old), cmds)
        self.assertFalse([c for c in cmds if c.startswith('sudo') and 'sh -c' in c],
                         'never a whole shell through sudo')
        ca = [c for c in cmds if 'ca-trust/source/anchors/acme-ca-' in c]
        self.assertEqual(len(ca), 1)
        self.assertTrue(any(c.startswith('rm -f /tmp/acme-') for c in cmds), 'uploads removed')
        self.assertEqual(t.served_places({}), [('srv01', 9090)])

    def test_another_file_wins_new_ones_removed(self):
        b, base, ssh = self.world(
            ensure_says='Using certificate /etc/cockpit/ws-certs.d/99-other.crt\n')
        with self.assertRaises(PluginError) as e:
            make('cockpit', '', self.CONF, FakeCtx(ssh=ssh)).deploy(b, {})
        self.assertIn('99-other.crt', str(e.exception))
        cmds = [c for c, _i in ssh.runs]
        self.assertIn('sudo -n rm -f /etc/cockpit/ws-certs.d/%s.crt /etc/cockpit/ws-certs.d/%s.key'
                      % (base, base), cmds)
        self.assertNotIn('sudo -n systemctl restart cockpit.service', cmds)

    def test_key_install_fails_both_new_files_removed(self):
        # 1.0.96: the .crt installed, the .key not - both taken out of ws-certs.d
        b, base, ssh = self.world()
        ssh.answers.insert(0, (r'install -m 0600 .*\.key', (1, '', 'install: No space left')))
        with self.assertRaises(PluginError) as e:
            make('cockpit', '', self.CONF, FakeCtx(ssh=ssh)).deploy(b, {})
        self.assertIn('No space left', str(e.exception))
        cmds = [c for c, _i in ssh.runs]
        self.assertIn('sudo -n rm -f /etc/cockpit/ws-certs.d/%s.crt /etc/cockpit/ws-certs.d/%s.key'
                      % (base, base), cmds)
        self.assertTrue(any(c.startswith('rm -f /tmp/acme-') for c in cmds), 'uploads removed')
        self.assertNotIn('sudo -n systemctl restart cockpit.service', cmds)

    def test_same_noop_sudo_password_and_debian_trust(self):
        now = '90-' + C.object_name(FakeBundle(), {})
        b, base, ssh = self.world(files='%s.crt\n%s.key\n' % (now, now))
        ssh.answers.insert(0, (r'test -d /etc/pki/ca-trust', (0, '/usr/local/share/ca-certificates\n',
                                                              '')))
        conf = dict(self.CONF, sudo_password='spw')
        ctx = FakeCtx(ssh=ssh)
        t = make('cockpit', '', conf, ctx)
        t.deploy(b, {'trust_ca': True, 'restart': False})
        sudo = [(c, i) for c, i in ssh.runs if c.startswith('sudo')]
        self.assertTrue(all(c.startswith("sudo -S -p '' ") and i == 'spw\n' for c, i in sudo))
        self.assertIn("sudo -S -p '' /usr/sbin/update-ca-certificates", [c for c, i in sudo])
        self.assertFalse([c for c, i in sudo if 'restart' in c])
        n = len(ssh.runs)
        self.assertIn('unchanged', t.deploy(b, {'trust_ca': True, 'restart': False}))
        self.assertFalse([c for c, _i in ssh.runs[n:] if c.startswith('sudo')])


# ---------------------------------------------------------------------------
# Veeam over PowerShell
# ---------------------------------------------------------------------------
class WinWorld(object):
    """A Windows server with Veeam: each PowerShell run answered by what it is."""
    def __init__(self, force=True, build='13.1.2.57', current='OLD', fail=None):
        self.force, self.build, self.current, self.fail = force, build, current, fail
        self.ssh = FakeSsh([(r'powershell', self.answer)])
        self.scripts = []

    def answer(self, cmd, inp):
        ps = script_of(cmd, self.ssh)
        self.scripts.append(ps)
        if self.fail and self.fail in ps:
            return 1, 'ERROR: it failed here\n', ''
        if '$adm = ' in ps:
            return 0, 'WHO svc-veeam|True\n', ''
        if "ContainsKey('Force')" in ps:
            return 0, 'FORCE %s\n%sCURRENT %s\n' % (self.force, 'BUILD %s\n' % self.build
                                                    if self.build else '', self.current), ''
        if 'Get-VBRCloudGatewayCertificate -ErrorAction Stop' in ps:
            return 0, 'CURRENT %s\n' % self.current, ''
        if 'Get-VBORestAPISettings' in ps:
            return 0, 'REST True 4443\n', ''
        return 0, 'STEP ok done\n', ''

    def ran(self, word):
        return [s for s in self.scripts if word in s]


def ca_bundle(tmpname='vbrca'):
    """A certificate as Veeam wants it: Basic Constraints CA, path length 0, RSA."""
    d = T.TMP
    j = lambda n: os.path.join(d, n)  # noqa: E731
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', j(tmpname + '.key'),
            '-out', j(tmpname + '.csr'), '-subj', '/CN=vbr.example.test')
    with open(j(tmpname + '.ext'), 'w') as fh:
        fh.write('basicConstraints=critical,CA:TRUE,pathlen:0\n'
                 'subjectAltName=DNS:vbr.example.test,DNS:vbr\n')
    openssl('x509', '-req', '-in', j(tmpname + '.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
            '-CAcreateserial', '-days', '10', '-out', j(tmpname + '.crt'), '-extfile',
            j(tmpname + '.ext'))
    T.CERTS[tmpname] = (j(tmpname + '.crt'), j(tmpname + '.key'))
    b = FakeBundle(tmpname)
    b.key_type = 'rsa-2048'
    return b


WIN = {'host': 'vbr.example.test', 'user': 'svc-veeam', 'auth': 'password', 'password': 'pw'}


class VbrTest(unittest.TestCase):
    def test_basic_constraints_read(self):
        b = ca_bundle()
        self.assertEqual(VBR.basic_constraints(b.cert_pem), (True, 0))
        self.assertIsNone(VBR.basic_constraints(FakeBundle().cert_pem))
        with open(os.path.join(T.TMP, 'ca.crt')) as fh:
            self.assertEqual(VBR.basic_constraints(fh.read())[0], True)

    def test_13(self):
        for version in ('', '13'):
            b = ca_bundle()
            w = WinWorld()
            ctx = FakeCtx(ssh=w.ssh)
            t = make('veeam_vbr', version, WIN, ctx)
            words = t.deploy(b, {})
            self.assertIn('(VBR 13)', words)
            sc = w.ran('Add-VBRBackupServerCertificate -Certificate')[0]
            self.assertIn('Import-Module Veeam.Backup.PowerShell', sc)
            self.assertIn('Import-PfxCertificate', sc)
            self.assertIn("$thumb = '%s'" % C.sha1_thumb(b), sc)
            self.assertIn('Get-VBRBackupServerCertificate -FromStore', sc)
            self.assertIn('Add-VBRBackupServerCertificate -Certificate $c -Force', sc)
            self.assertNotIn('netsh', sc)
            self.assertIn("'Root'", sc, 'the CA certificate trusted')
            self.assertTrue([s for lvl, s in ctx.steps if lvl == 'warn' and 'restart' in s])
            self.assertEqual(len([p for p, _d, _m in w.ssh.puts if p.endswith('.pfx')]), 1)
            self.assertEqual(t.served_places({}), [('vbr.example.test', 443 if version else 9419)])

    def test_123_netsh_and_no_force(self):
        for version, force in (('', False), ('12.3', False)):
            b = ca_bundle()
            w = WinWorld(force=force, build='12.3.2.4465')
            t = make('veeam_vbr', version, WIN, FakeCtx(ssh=w.ssh))
            t.deploy(b, {'restart_services': 'VeeamBackupSvc'})
            sc = w.ran('Add-VBRBackupServerCertificate -Certificate')[0]
            self.assertIn('Add-VBRBackupServerCertificate -Certificate $c | Out-Null', sc)
            self.assertNotIn('-Force |', sc)
            self.assertIn('netsh http delete sslcert ipport=0.0.0.0:9419', sc)
            self.assertIn('netsh http add sslcert ipport=0.0.0.0:9419 certhash=$thumb appid='
                          "'{284175c4-aa3e-4c6f-a2dd-5a4c80552eb9}' certstorename=MY", sc)
            self.assertIn("Restart-Service -Name 'VeeamBackupSvc' -Force", sc)
            self.assertEqual(VBR.VeeamVbrTarget.served_wait({'restart_services': 'x'}), (20, 30))
        w = WinWorld(force=False, build='12.3.2.4465')
        make('veeam_vbr', '12.3', WIN, FakeCtx(ssh=w.ssh)).deploy(ca_bundle(),
                                                                   {'rest_binding': False})
        self.assertNotIn('netsh', w.ran('Add-VBRBackupServerCertificate -Certificate')[0])

    def test_detected_by_the_cmdlet_without_a_build(self):
        w = WinWorld(force=False, build='')
        make('veeam_vbr', '', WIN, FakeCtx(ssh=w.ssh)).deploy(ca_bundle(), {})
        self.assertIn('netsh http add', w.ran('Add-VBRBackupServerCertificate')[-1])

    def test_refused_before_any_change(self):
        for version, force, build, fit in (('12.3', True, '13.1.2.57', 'VBR 13.0 - 13.1'),
                                           ('13', False, '12.3.2.4465', 'VBR 12.3'),
                                           ('13', False, '', 'VBR 12.3')):
            w = WinWorld(force=force, build=build)
            with self.assertRaises(PluginError) as e:
                make('veeam_vbr', version, WIN, FakeCtx(ssh=w.ssh)).deploy(ca_bundle(), {})
            self.assertFalse(e.exception.retry)
            self.assertIn('"%s"' % fit, str(e.exception))
            self.assertFalse(w.ran('Add-VBRBackupServerCertificate -Certificate'))
            self.assertFalse(w.ssh.puts, 'nothing uploaded')

    def test_not_a_ca_certificate_refused(self):
        w = WinWorld()
        leaf = FakeBundle()
        leaf.key_type = 'ec-256'
        with self.assertRaises(PluginError) as e:
            make('veeam_vbr', '13', WIN, FakeCtx(ssh=w.ssh)).deploy(leaf, {})
        self.assertIn('Basic Constraints', str(e.exception))
        self.assertIn('RSA', str(e.exception))
        self.assertFalse(w.ssh.runs, 'refused before signing in')
        make('veeam_vbr', '13', WIN, FakeCtx(ssh=w.ssh)).deploy(FakeBundle(),
                                                                 {'allow_leaf': True})
        self.assertTrue(w.ran('Add-VBRBackupServerCertificate'))

    def test_same_noop_and_failure(self):
        b = ca_bundle()
        w = WinWorld(current='OLD')
        ctx = FakeCtx(ssh=w.ssh)
        t = make('veeam_vbr', '13', WIN, ctx)
        t.deploy(b, {})
        w.current = C.sha1_thumb(b)
        n = len(w.scripts)
        self.assertIn('unchanged', t.deploy(b, {}))
        self.assertFalse([s for s in w.scripts[n:] if 'Add-VBRBackupServerCertificate -C' in s])
        w2 = WinWorld(fail='Add-VBRBackupServerCertificate -Certificate')
        with self.assertRaises(PluginError) as e:
            make('veeam_vbr', '13', WIN, FakeCtx(ssh=w2.ssh)).deploy(ca_bundle(), {})
        self.assertIn('it failed here', str(e.exception))
        self.assertTrue(w2.ran('Remove-Item -LiteralPath'), 'the PKCS#12 is deleted')

    def test_try(self):
        w = WinWorld()
        self.assertIn('13.1.2.57', make('veeam_vbr', '', WIN, FakeCtx(ssh=w.ssh)).test())
        with self.assertRaises(PluginError):
            make('veeam_vbr', '12.3', WIN, FakeCtx(ssh=WinWorld().ssh)).test()
        w = WinWorld(build='14.0.0.1')
        make('veeam_vbr', '13', WIN, FakeCtx(ssh=w.ssh)).deploy(ca_bundle(), {})


class CloudConnectTest(unittest.TestCase):
    def test_deploy(self):
        b = FakeBundle()
        w = WinWorld()
        ctx = FakeCtx(ssh=w.ssh)
        t = make('veeam_cloud_connect', '', WIN, ctx)
        t.deploy(b, {})
        sc = w.ran('Add-VBRCloudGatewayCertificate')[0]
        self.assertIn('Get-VBRCloudGatewayCertificate -FromStore', sc)
        self.assertIn('Add-VBRCloudGatewayCertificate -Certificate $c | Out-Null', sc)
        self.assertIn('Import-PfxCertificate', sc)
        self.assertTrue([s for _l, s in ctx.steps if C.sha1_thumb(b) in s], 'thumbprint said')
        self.assertEqual(t.served_places({}), [])
        w.current = C.sha1_thumb(b)
        n = len(w.scripts)
        self.assertIn('unchanged', t.deploy(b, {}))
        self.assertFalse([s for s in w.scripts[n:] if 'Add-VBR' in s])

    def test_no_chain_import_when_off(self):
        w = WinWorld()
        make('veeam_cloud_connect', '', WIN, FakeCtx(ssh=w.ssh)).deploy(
            FakeBundle(), {'trust_chain': 'false'})
        self.assertNotIn('X509Store', w.ran('Add-VBRCloudGatewayCertificate')[0])


class Vb365Test(unittest.TestCase):
    def test_rest_and_server(self):
        b = FakeBundle()
        w = WinWorld()
        t = make('veeam_vb365', '', WIN, FakeCtx(ssh=w.ssh))
        self.assertIn('REST API enabled/port: True 4443', t.test())
        words = t.deploy(b, {'server': True, 'rest_port': 4443})
        self.assertIn('the REST API, the server certificate', words)
        sc = w.ran('Set-VBORestAPISettings')[0]
        self.assertIn('Import-Module Veeam.Archiver.PowerShell', sc)
        pfx = [p for p, _d, _m in w.ssh.puts if p.endswith('.pfx')][0]
        self.assertIn("$pfx = '%s'" % pfx, sc)
        self.assertIn('Set-VBORestAPISettings -EnableService -HTTPSPort 4443 -CertificateFilePath '
                      '$pfx -CertificatePassword $pw', sc)
        self.assertIn('Set-VBOSecuritySettings -CertificateFilePath $pfx -CertificatePassword '
                      '$pw -Force', sc)
        self.assertNotIn('Set-VBOOperatorAuthenticationSettings', sc)
        self.assertIn('Remove-Item -LiteralPath $pfx', sc)
        self.assertEqual(t.served_places({'rest_port': 4443}), [('vbr.example.test', 4443)])
        self.assertIn('unchanged', t.deploy(b, {'server': True, 'rest_port': 4443}))

    def test_choices_and_errors(self):
        w = WinWorld()
        t = make('veeam_vb365', '', WIN, FakeCtx(ssh=w.ssh))
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'rest': False})
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'rest_port': 70000})
        t.deploy(FakeBundle(), {'rest': False, 'operator': True, 'tenant': True})
        sc = w.ran('Set-VBOOperatorAuthenticationSettings')[0]
        self.assertIn('Set-VBOTenantAuthenticationSettings -EnableAuthentication', sc)
        self.assertNotIn('Set-VBORestAPISettings', sc)
        self.assertEqual(t.served_places({'rest': False}), [])

    def test_not_an_administrator(self):
        ssh = FakeSsh([(r'powershell', lambda c, i: (0, 'WHO someone|False\n', ''))])
        with self.assertRaises(PluginError) as e:
            make('veeam_vb365', '', WIN, FakeCtx(ssh=ssh)).test()
        self.assertIn('not as an administrator', str(e.exception))


# ---------------------------------------------------------------------------
# Nutanix, the 7.5 version
# ---------------------------------------------------------------------------
class Nutanix75Test(unittest.TestCase):
    CID = '00061de0-6c4e-25a1-0000-00000000aa11'

    def routes(self):
        p = r'/api/clustermgmt/v4\.4/config/clusters/%s/ssl-certificate' % self.CID
        return [('GET', p, (200, {'data': {'privateKeyAlgorithm': 'RSA_2048'}},
                            {'ETag': 'etag-1'})),
                ('PUT', p, (202, {'data': {'extId': 'task-1'}})),
                ('GET', r'/api/prism/v4\.4/config/tasks/task-1',
                 (200, {'data': {'status': 'SUCCEEDED'}}))]

    def test_api_key_v44(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        t = make('nutanix', '7.5', {'host': 'pc', 'api_key': 'KEY', 'cluster': self.CID}, ctx)
        t._sleep = lambda s: None
        t.deploy(b, {'algorithm': 'ECDSA_256'})
        put = ctx.find('PUT', r'ssl-certificate')[0]
        self.assertEqual(put['headers']['X-ntnx-api-key'], 'KEY')
        self.assertNotIn('Authorization', put['headers'])
        self.assertEqual(put['headers']['If-Match'], 'etag-1')
        body = ctx.json(put)
        self.assertEqual(base64.b64decode(body['publicCertificate']).decode(), b.cert_pem)
        self.assertEqual(body['privateKeyAlgorithm'], 'ECDSA_256')

    def test_password_and_key_types(self):
        ctx = FakeCtx(self.routes())
        t = make('nutanix', '7.5', {'host': 'pc', 'auth': 'password', 'user': 'admin',
                                    'password': 'pw', 'cluster': self.CID}, ctx)
        t._sleep = lambda s: None
        t.deploy(FakeBundle(), {'algorithm': 'RSA_4096'})
        self.assertTrue(ctx.calls[0]['headers']['Authorization'].startswith('Basic '))
        b = FakeBundle()
        b.key_type = 'ec-521'
        with self.assertRaises(PluginError) as e:
            t.deploy(b, {'force': True})
        self.assertIn('P-521', str(e.exception))
        with self.assertRaises(PluginError):
            make('nutanix', '7.5', {'host': 'pc', 'cluster': self.CID}, FakeCtx()).test()

    def test_plain_unchanged(self):
        """The plain module still sends HTTP basic on v4.3, as before."""
        reg = Registry(extra_dirs=[]).reload()
        plain = reg.get('target', 'nutanix', '')
        self.assertEqual(plain({'host': 'pc'}, FakeCtx()).v(), 'v4.3')


# ---------------------------------------------------------------------------
class GuidesTest(unittest.TestCase):
    def test_a_guide_for_each_kind_and_version_in_both_languages(self):
        want = dict(KINDS)
        for kind, vers in want.items():
            for v in vers:
                for suffix in ('.md', '.cs.md'):
                    p = os.path.join(GUIDES, '%s%s%s' % (kind, '@' + v if v else '', suffix))
                    with open(p, encoding='utf-8') as f:
                        md = f.read()
                    self.assertTrue(md.startswith('# '), p)
                    self.assertIn('```', md, p)
                    self.assertGreater(len(md), 1500, p)
                    if suffix == '.cs.md':
                        self.assertTrue(re.search('[ěščřžýáíéůú]', md), p)
                        self.assertIn('Vyplnění v acme', md, p)
                    else:
                        self.assertIn('Fill in acme', md, p)
        for suffix in ('.md', '.cs.md'):
            p = os.path.join(GUIDES, 'nutanix@7.5' + suffix)
            self.assertTrue(os.path.isfile(p), p)
        # the existing plain guides are not touched by this group
        for kind in ('synology', 'proxmox', 'proxmox_backup', 'kubernetes'):
            self.assertFalse([f for f in os.listdir(GUIDES) if f.startswith(kind + '@')], kind)


if __name__ == '__main__':
    unittest.main(verbosity=1)
