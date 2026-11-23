#!/usr/bin/env python3
"""Hunt 1.0.143, run w3, area "targets a - flowmon": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_rw3_targetsaf.py

- avi: a virtual service's other certificate of the same kind as acme's was kept beside it
  (the Controller takes one EC and one RSA at most: refused), and with two other ones both
  went - the one of the other kind is kept now.
- f5: with no acme entry yet, the "default" entry was replaced whatever its kind - a profile
  with an RSA and an EC entry got two EC keys (refused); the entry of the same kind is taken.
- cisco_fmc: the deployment request went without the "version" deployabledevices says (the
  field the FMC's DeploymentRequest asks for).
- cisco_asa: an error page that echoes the import command put the PKCS#12's one-time
  password into the job's error words.
- the command line had no form of the page's "Load the list" (a form's field of the type
  catalog: the HTTPS Inspection rules of a Check Point, the listeners of an Azure gateway):
  acme --target-list NAME FIELD [--set ...] (and --source-list, --validation-list).
- barracuda_cgf: the entry read back after the import was compared by its SHA-256
  fingerprint only - an answer giving SHA-1 made every deployment an error.
"""
import json
import os
import sys
import unittest
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as TT  # noqa: E402
from test_targets import FakeBundle, FakeCtx, make  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


def body(call):
    return json.loads(call['body'])


# ---------------------------------------------------------------------------
class AviSameKindTest(unittest.TestCase):
    def run_vs(self, fam, cur_refs, algos):
        objs = [{'uuid': u, 'name': u, 'key_params': {'algorithm': a}} for u, a in algos.items()]
        vs = {'uuid': 'virtualservice-1', 'name': 'vs-www',
              'ssl_key_and_certificate_refs': ['https://avi.test/api/sslkeyandcertificate/%s'
                                               % u for u in cur_refs]}

        def find(call):
            q = call['query']
            if 'name' in q:
                return 200, {'results': [o for o in objs if o['name'] == q['name'][0]]}
            return 200, {'count': len(objs), 'results': objs}

        def add(call):
            o = dict(body(call), uuid='sslkeyandcertificate-new%d' % len(objs))
            objs.append(o)
            return 201, o

        def patch(call):
            vs['ssl_key_and_certificate_refs'] = body(call)['replace'][
                'ssl_key_and_certificate_refs']
            return 200, vs
        ctx = FakeCtx([
            ('POST', r'/login$', (200, {}, {'Set-Cookie': 'csrftoken=C; Path=/, '
                                                          'sessionid=S; Path=/'})),
            ('POST', r'/logout$', (200, {})),
            ('GET', r'/api/sslkeyandcertificate\?', find),
            ('POST', r'/api/sslkeyandcertificate$', add),
            ('GET', r'/api/virtualservice\?name=vs-www$', lambda c: (200, {'results': [vs]})),
            ('PATCH', r'/api/virtualservice/virtualservice-1$', patch),
        ])
        b = FakeBundle()
        b.family = fam
        make('avi', {'host': 'avi.test', 'user': 'u', 'password': 'p'}, ctx).deploy(
            b, {'virtual_services': 'vs-www', 'ca_certs': False})
        return [r.rsplit('/', 1)[1] for r in vs['ssl_key_and_certificate_refs']]

    def test_same_kind_replaced(self):
        # the VS has the RSA default only; an RSA certificate takes its place
        got = self.run_vs('rsa', ['def-rsa'], {'def-rsa': 'SSL_KEY_ALGORITHM_RSA'})
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].startswith('sslkeyandcertificate-new'))
        # an EC one goes beside it (as before)
        got = self.run_vs('ec', ['def-rsa'], {'def-rsa': 'SSL_KEY_ALGORITHM_RSA'})
        self.assertEqual(got[0], 'def-rsa')
        self.assertEqual(len(got), 2)

    def test_other_kind_kept_of_two(self):
        algos = {'def-rsa': 'SSL_KEY_ALGORITHM_RSA', 'def-ec': 'SSL_KEY_ALGORITHM_EC'}
        got = self.run_vs('ec', ['def-rsa', 'def-ec'], algos)
        self.assertEqual(got[0], 'def-rsa')
        self.assertEqual(len(got), 2)
        self.assertNotIn('def-ec', got)

    def test_kind_unknown_as_before(self):
        got = self.run_vs('rsa', ['other'], {'other': ''})
        self.assertEqual(got[0], 'other')
        self.assertEqual(len(got), 2)
        got = self.run_vs('rsa', ['x1', 'x2'], {'x1': '', 'x2': ''})
        self.assertEqual(len(got), 1)


# ---------------------------------------------------------------------------
class F5SameKindTest(unittest.TestCase):
    def routes(self, kinds, chains):
        def cert_get(call):
            name = call['path'].rsplit('/', 1)[1].replace('~', '/')
            if name in kinds:
                return 200, {'name': name, 'keyType': kinds[name]}
            return 404, {'code': 404}
        return [
            ('POST', r'/mgmt/shared/authn/login$', (200, {'token': {'token': 'TOK'}})),
            ('DELETE', r'/mgmt/shared/authz/tokens/TOK', (200, {})),
            ('GET', r'/mgmt/tm/sys/crypto/cert\?', (200, {'items': []})),
            ('GET', r'/mgmt/tm/sys/crypto/cert/', cert_get),
            ('GET', r'/mgmt/tm/sys/crypto/key/', (404, {})),
            ('POST', r'/mgmt/shared/file-transfer/uploads/', (200, {})),
            ('POST', r'/mgmt/tm/sys/crypto/(cert|key)$', (200, {})),
            ('POST', r'/mgmt/tm/util/unix-rm', (200, {})),
            ('GET', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, {
                'name': 'www_ssl', 'certKeyChain': chains})),
            ('PATCH', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, {})),
            ('POST', r'/mgmt/tm/sys/config$', (200, {})),
        ]

    CHAINS = [{'name': 'default', 'cert': '/Common/default.crt', 'key': '/Common/default.key'},
              {'name': 'ecdsa', 'cert': '/Common/ec.crt', 'key': '/Common/ec.key'}]
    KINDS = {'/Common/default.crt': 'rsa-public', '/Common/ec.crt': 'ec-public'}

    def deploy(self, b, kinds):
        ctx = FakeCtx(self.routes(kinds, [dict(c) for c in self.CHAINS]))
        make('f5', {'host': 'bigip', 'user': 'u', 'password': 'p'}, ctx).deploy(
            b, {'profiles': 'www_ssl'})
        return body(ctx.find('PATCH', 'client-ssl')[0])['certKeyChain']

    def test_ec_takes_the_ec_entry(self):
        b = FakeBundle()
        b.family = 'ec'
        got = self.deploy(b, self.KINDS)
        name = '/Common/' + C.object_name(b, {})
        self.assertEqual(got[0]['cert'], '/Common/default.crt')      # the RSA one stays
        self.assertEqual((got[1]['name'], got[1]['cert']), ('ecdsa', name))

    def test_rsa_takes_default(self):
        b = FakeBundle()
        b.family = 'rsa'
        got = self.deploy(b, self.KINDS)
        self.assertEqual(got[0]['cert'], '/Common/' + C.object_name(b, {}))
        self.assertEqual(got[1]['cert'], '/Common/ec.crt')

    def test_unknown_kind_as_before(self):
        b = FakeBundle()
        b.family = 'ec'
        got = self.deploy(b, {})
        self.assertEqual(got[0]['cert'], '/Common/' + C.object_name(b, {}))   # "default"


# ---------------------------------------------------------------------------
class CgfSha1Test(unittest.TestCase):
    BOX = '/rest/config/v1/box/store/certificates'

    def test_sha1_fingerprint_read_back(self):
        import hashlib
        b = FakeBundle()
        sha1 = hashlib.sha1(C.pem_to_der(b.cert_pem)).hexdigest().upper()
        state = {'imported': False}

        def entry(call):
            if state['imported']:
                return 200, {'name': 'vpn', 'subCertificates': [
                    {'fingerprint': ':'.join(sha1[i:i + 2] for i in range(0, 40, 2))}]}
            return 200, {'name': 'vpn', 'subCertificates': [{'fingerprint': 'AA:BB'}]}

        def imp(call):
            state['imported'] = True
            return 200, {}
        ctx = FakeCtx([('GET', self.BOX + r'/vpn$', entry), ('PUT', self.BOX + r'/vpn$', imp)])
        t = make('barracuda_cgf', {'host': 'cgf', 'token': 'T'}, ctx)
        self.assertIn('imported into vpn', t.deploy(b, {'entry': 'vpn'}))
        # the same again: known by its SHA-1 - nothing sent
        ctx.calls = []
        self.assertIn('unchanged', t.deploy(b, {'entry': 'vpn'}))
        self.assertFalse(ctx.find('PUT', ''))
        # another certificate read back is still an error
        state['imported'] = False
        ctx.routes[0] = ('GET', self.BOX + r'/vpn$', lambda c: (200, {'subCertificates': [
            {'fingerprint': '11' * 20}]}))
        with self.assertRaises(C.PluginError):
            t.deploy(b, {'entry': 'vpn', 'force': True})


# ---------------------------------------------------------------------------
class FmcDeployVersionTest(unittest.TestCase):
    DOM = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'

    def deploy(self, items):
        base = r'/api/fmc_config/v1/domain/%s' % self.DOM
        ctx = FakeCtx([
            ('POST', r'generatetoken$', (204, b'', {'X-auth-access-token': 'T',
                                                    'DOMAIN_UUID': self.DOM})),
            ('GET', base + r'/deployment/deployabledevices', (200, {'items': items})),
            ('POST', base + r'/deployment/deploymentrequests$', (202, {})),
        ])
        t = make('cisco_fmc', {'host': 'fmc', 'user': 'u', 'password': 'p'}, ctx)
        did = []
        t.deploy_devices({'devices': 'ftd-1\nftd-2'}, did)
        return body(ctx.find('POST', 'deploymentrequests')[0])

    def test_version_sent(self):
        got = self.deploy([
            {'name': 'ftd-1', 'version': '1700000000001', 'device': {'id': 'D1'}},
            {'name': 'ftd-2', 'version': '1700000000009', 'device': {'id': 'D2'}},
            {'name': 'ftd-3', 'version': '1800000000000', 'device': {'id': 'D3'}}])
        self.assertEqual(got['deviceList'], ['D1', 'D2'])
        self.assertEqual(got['version'], '1700000000009')     # the newest of the ones asked

    def test_no_version_said_as_before(self):
        got = self.deploy([{'name': 'ftd-1', 'device': {'id': 'D1'}}])
        self.assertNotIn('version', got)
        self.assertEqual(got['deviceList'], ['D1'])


# ---------------------------------------------------------------------------
class AsaPasswordTest(unittest.TestCase):
    def test_error_echo_masked(self):
        seen = {}

        def config(call):
            b = call['body'].decode()
            if 'pkcs12 ' not in b:
                return 200, 'INFO: done'
            seen['pw'] = b.split('pkcs12 ', 1)[1].split()[0]
            return 400, ('<html>ERROR: ' + b.splitlines()[2][:150] + '</html>').encode()
        ctx = FakeCtx([
            ('GET', r'/admin/exec/show\+running-config\+crypto', (200, '')),
            ('POST', r'/admin/config$', config),
        ])
        t = make('cisco_asa', {'host': 'asa', 'user': 'u', 'password': 'p'}, ctx)
        with self.assertRaises(C.PluginError) as e:
            t.deploy(FakeBundle(), {'trust_points': 'outside'})
        self.assertTrue(seen.get('pw'))
        self.assertNotIn(seen['pw'], str(e.exception))
        self.assertIn('crypto ca import', str(e.exception))


# ---------------------------------------------------------------------------
PLUGIN = """
from acmelib.plugins.targets._common import Base, field


class ListedTarget(Base):
    kind = 'w3listed'
    title = 'A list to load'
    discovery = False
    fields = [field('host', 'Host', 'text')]
    deploy_fields = [field('zone', 'Zone', 'catalog', catalog='zones'),
                     field('region', 'Region', 'text')]

    def catalog(self, key):
        assert key == 'zones'
        self.ctx.step('asked %s for its zones' % self.c('host'))
        reg = self.c('region') or 'eu'
        return {'options': [['z1', 'Zone one (%s)' % reg], ['z2', 'Zone two']],
                'sets': {'z1': {'region': reg}}, 'said': '2 zones', 'pick': 'z2'}

    def deploy(self, bundle, options):
        return 'nothing'
"""


class CliListTest(unittest.TestCase):
    """acme --target-list NAME FIELD (and --source-list, --validation-list): the page's "Load
    the list" of a form's field on the command line."""

    def test_list(self):
        import subprocess
        import tempfile
        root = os.path.dirname(HERE)
        tmp = tempfile.mkdtemp(prefix='acme-rw3list-')
        os.makedirs(os.path.join(tmp, 'plugins', 'targets'))
        with open(os.path.join(tmp, 'plugins', 'targets', 'w3listed.py'), 'w') as f:
            f.write(PLUGIN)
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            f.write('{}')
        env = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
        env.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(tmp, 'config.json'),
                   ACME_STATE=tmp, ACME_RUN=tmp, ACME_LOGDIR=tmp, NO_COLOR='1',
                   ACME_PLUGINS=os.path.join(tmp, 'plugins'))

        def run(*a):
            return subprocess.run([sys.executable, os.path.join(root, 'acme.py')] + list(a),
                                  env=env, capture_output=True, text=True, timeout=240)
        got = run('--target-add', 'L1', '--kind', 'w3listed', '--set', 'host=dev1')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        got = run('--target-list', 'L1', 'zone')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('Zone one (eu)', got.stdout)
        self.assertIn('* z2', got.stdout)
        self.assertIn('asked dev1 for its zones', got.stdout)
        got = run('--target-list', 'L1', 'zone', '--set', 'region=us', '--json')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        j = json.loads(got.stdout)
        self.assertEqual(j['options'][0], ['z1', 'Zone one (us)'])
        self.assertEqual(j['sets'], {'z1': {'region': 'us'}})
        got = run('--target-list', 'L1', 'region')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('no list to load', got.stdout + got.stderr)
        got = run('--target-list', 'nope', 'zone')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('there is no target nope', got.stdout + got.stderr)


class ConsoleListTest(unittest.TestCase):
    """The console's target menu offers "Load a list of its form" (acme --target-list)."""

    class Con(object):
        def __init__(self, chooses):
            self.chooses, self.cmds, self.offered = list(chooses), [], []

        def choose(self, title, options, words='', cur=0):
            self.offered.append(options)
            want = self.chooses.pop(0)
            assert want is None or want in [o[0] for o in options], (want, options)
            return want

        def cmd(self, *args):
            self.cmds.append(args)
            return 0

        def live(self, fn):
            fn()

        def pause(self):
            pass

    def test_menu(self):
        from acmelib.certs import console as CO
        orig = CO._plugin
        CO._plugin = lambda *a, **k: {
            'fields': [{'key': 'host', 'type': 'text'}],
            'deploy_fields': [{'key': 'https_rule', 'type': 'catalog', 'label': 'Rule'},
                              {'key': 'gateway', 'type': 'catalog', 'label': 'Gateway'}]}
        try:
            con = self.Con(['list', 'gateway'])
            CO.fam_do(con, 'target', {'name': 'cp1', 'kind': 'checkpoint', 'enabled': 1})
            self.assertIn('Load a list of its form (Rule, Gateway)',
                          [o[1] for o in con.offered[0]])
            self.assertEqual(con.cmds, [('--target-list', 'cp1', 'gateway')])
            CO._plugin = lambda *a, **k: {'fields': [], 'deploy_fields': []}
            con = self.Con([None])
            CO.fam_do(con, 'target', {'name': 'x', 'kind': 'local', 'enabled': 1})
            self.assertNotIn('list', [o[0] for o in con.offered[0]])
        finally:
            CO._plugin = orig


if __name__ == '__main__':
    unittest.main()
