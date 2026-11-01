#!/usr/bin/env python3
"""The target modules added after the first ones - cloud services, hypervisors,
server controllers, firewalls, load balancers, proxies, appliances - without a
network and without a device.

    python3 -m unittest test/test_targets_more.py   (or python3 test/test_targets_more.py)

The fake Context, SSH session and certificates are those of test_targets.py:
every request is recorded and answered from canned answers, and the tests
look at what was asked - URLs, sign-in headers and signatures (at a fixed
time), bodies - at the same certificate twice being a no-op, at old ones
being cleaned up and at errors said in words.
"""
import base64
import email.parser
import email.policy
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx, make, read  # noqa: E402
from acmelib.plugins.base import PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

NEW_KINDS = ('aws_acm', 'azure_keyvault', 'gcp_certmanager', 'cloudflare_ssl', 'vcenter', 'esxi',
             'redfish', 'sophos', 'kemp', 'cisco_ise', 'haproxy', 'traefik', 'caddy',
             'nginx_unit', 'zimbra', 'truenas', 'docker_swarm', 'strongswan', 'fritzbox',
             'unifi_os')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class OpensslCtx(FakeCtx):
    """A FakeCtx with the openssl program (for JWTs and encrypted keys)."""
    def openssl(self, args, data=None, timeout=60):
        return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                              check=True, timeout=timeout).stdout


def parts_of(call):
    """The parts of a multipart body: {name: (filename, bytes)}."""
    ctype = call['headers'].get('Content-Type')
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b'Content-Type: ' + ctype.encode() + b'\r\n\r\n' + call['body'])
    out = {}
    for p in msg.iter_parts():
        out[p.get_param('name', header='content-disposition')] = (
            p.get_filename(), p.get_payload(decode=True))
    return out


def sums(files):
    """What sha256sum would say of these {path: bytes}."""
    return ''.join('%s  %s\n' % (hashlib.sha256(d).hexdigest(), p) for p, d in files.items())


def b64d(s):
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Cloud
# ---------------------------------------------------------------------------
class AwsAcmTest(unittest.TestCase):
    ARN = 'arn:aws:acm:eu-central-1:123456789012:certificate/abc'

    def setUp(self):
        self.serial = None

        def acm(call):
            target = call['headers']['X-Amz-Target'].split('.')[1]
            body = json.loads(call['body'])
            if target == 'ImportCertificate':
                return 200, {'CertificateArn': body.get('CertificateArn') or self.ARN}
            if target == 'DescribeCertificate':
                if self.serial is None:
                    return 400, {'__type': 'com.amazon#ResourceNotFoundException',
                                 'message': 'no such'}
                return 200, {'Certificate': {'Serial': self.serial}}
            if target == 'ListCertificates':
                return 200, {'CertificateSummaryList': [{'CertificateArn': self.ARN}]}
            return 400, {'__type': 'x#AccessDeniedException', 'message': 'not allowed'}
        self.ctx = FakeCtx([('POST', r'^https://acm\.eu-central-1\.amazonaws\.com/$', acm)])
        self.t = make('aws_acm', {'access_key_id': 'AKIDEXAMPLE', 'region': 'eu-central-1',
                                  'secret_access_key': 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'},
                      self.ctx)
        self.t._amz_date = '20261101T120000Z'

    def check_signature(self, call):
        h = {k.lower(): v for k, v in call['headers'].items()}
        auth = h['authorization']
        self.assertTrue(auth.startswith('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261101/'
                                        'eu-central-1/acm/aws4_request, '))
        signed = re.search(r'SignedHeaders=([^,]+)', auth).group(1)
        self.assertEqual(signed, 'accept;content-type;host;x-amz-date;x-amz-target')
        # the signature, worked out here again
        canon = '\n'.join(['POST', '/', '', ''.join('%s:%s\n' % (k, h[k])
                                                    for k in signed.split(';')),
                           signed, hashlib.sha256(call['body']).hexdigest()])
        sts = '\n'.join(['AWS4-HMAC-SHA256', '20261101T120000Z',
                         '20261101/eu-central-1/acm/aws4_request',
                         hashlib.sha256(canon.encode()).hexdigest()])
        k = ('AWS4' + 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY').encode()
        for part in ('20261101', 'eu-central-1', 'acm', 'aws4_request'):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        self.assertTrue(auth.endswith('Signature=' + sig))

    def test_import_reimport_noop(self):
        a = FakeBundle('a')
        words = self.t.deploy(a, {'tags': 'Owner=it\nApp = web'})
        self.assertIn(self.ARN, words)
        imp = [c for c in self.ctx.calls
               if c['headers']['X-Amz-Target'].endswith('ImportCertificate')]
        self.assertEqual(len(imp), 1)
        self.check_signature(imp[0])
        self.assertEqual(imp[0]['headers']['Content-Type'], 'application/x-amz-json-1.1')
        body = json.loads(imp[0]['body'])
        self.assertEqual(b64d(body['Certificate']).decode(), a.cert_pem)
        self.assertEqual(b64d(body['PrivateKey']).decode(), a.key_pem)
        self.assertEqual(b64d(body['CertificateChain']).decode(), a.chain_pems[0])
        self.assertNotIn('CertificateArn', body)
        self.assertEqual(body['Tags'], [{'Key': 'Owner', 'Value': 'it'},
                                        {'Key': 'App', 'Value': 'web'}])
        # the same again: ACM has it (its serial) - nothing imported
        self.serial = ':'.join(re.findall('..', a.serial.lower()))
        self.assertTrue(self.t.deploy(a, {}).startswith('unchanged'))
        self.assertEqual(len([c for c in self.ctx.calls if 'Import' in
                              c['headers']['X-Amz-Target']]), 1)
        # a renewal: re-imported into the same ARN, no tags
        self.t.deploy(FakeBundle('b'), {'tags': 'Owner=it'})
        body = json.loads(self.ctx.calls[-1]['body'])
        self.assertEqual(body['CertificateArn'], self.ARN)
        self.assertNotIn('Tags', body)

    def test_errors(self):
        self.assertIn('1 certificate', self.t.test())
        with self.assertRaises(PluginError) as e:
            self.t.call('Nope', {})
        self.assertIn('AccessDeniedException - not allowed', str(e.exception))
        self.assertFalse(e.exception.retry)
        with self.assertRaises(PluginError) as e:
            self.t.deploy(FakeBundle(), {'certificate_arn': self.ARN})
        self.assertIn('no certificate', str(e.exception))
        bad = make('aws_acm', {'access_key_id': 'A', 'secret_access_key': 'B',
                               'region': 'mars'}, FakeCtx())
        with self.assertRaises(PluginError):
            bad.test()


class AzureKeyVaultTest(unittest.TestCase):
    def setUp(self):
        self.x5t = None

        def get(call):
            if self.x5t is None:
                return 404, {'error': {'code': 'CertificateNotFound', 'message': 'not found'}}
            return 200, {'x5t': self.x5t}
        self.ctx = FakeCtx([
            ('POST', r'^https://login\.microsoftonline\.com/tid/oauth2/v2\.0/token$',
             (200, {'access_token': 'TOK', 'expires_in': 3600})),
            ('GET', r'/certificates/www-cert\?api-version=7\.4$', get),
            ('POST', r'/certificates/www-cert/import\?api-version=7\.4$',
             (200, {'id': 'https://kv-firma.vault.azure.net/certificates/www-cert/0a1b'})),
        ])
        self.t = make('azure_keyvault', {'vault': 'kv-firma', 'tenant_id': 'tid',
                                         'client_id': 'cid', 'client_secret': 'sec'}, self.ctx)

    def test_import_then_noop(self):
        a = FakeBundle()
        words = self.t.deploy(a, {'cert_name': 'www-cert'})
        self.assertIn('version 0a1b', words)
        tok = self.ctx.calls[0]
        q = urllib.parse.parse_qs(tok['body'].decode())
        self.assertEqual(q['scope'], ['https://vault.azure.net/.default'])
        self.assertEqual(q['grant_type'], ['client_credentials'])
        imp = self.ctx.find('POST', r'/import')[0]
        self.assertEqual(imp['headers']['Authorization'], 'Bearer TOK')
        self.assertTrue(imp['url'].startswith('https://kv-firma.vault.azure.net/'))
        body = json.loads(imp['body'])
        self.assertEqual(body['value'], a.key_pem + a.fullchain_pem)
        self.assertEqual(body['policy']['secret_props']['contentType'], 'application/x-pem-file')
        self.x5t = base64.urlsafe_b64encode(bytes.fromhex(C.sha1_thumb(a))).rstrip(b'=').decode()
        self.assertTrue(self.t.deploy(a, {'cert_name': 'www-cert'}).startswith('unchanged'))
        self.assertEqual(len(self.ctx.find('POST', r'/import')), 1)
        with self.assertRaises(PluginError):
            self.t.deploy(a, {'cert_name': 'bad.name'})

    def test_bad_secret(self):
        ctx = FakeCtx([('POST', r'/token$', (401, {'error': 'invalid_client',
                                                   'error_description': 'AADSTS7000215'}))])
        t = make('azure_keyvault', {'vault': 'kv-firma', 'tenant_id': 'tid', 'client_id': 'c',
                                    'client_secret': 'x'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertFalse(e.exception.retry)
        self.assertIn('AADSTS7000215', str(e.exception))


class GcpCertManagerTest(unittest.TestCase):
    def setUp(self):
        key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                              'rsa_keygen_bits:2048'], capture_output=True, check=True).stdout
        self.sa = {'type': 'service_account', 'project_id': 'proj-1',
                   'client_email': 'acme@proj-1.iam.gserviceaccount.com',
                   'private_key': key.decode(), 'private_key_id': 'kid1'}
        self.have = None
        base = r'^https://certificatemanager\.googleapis\.com/v1/projects/proj-1/locations/global'
        self.ctx = OpensslCtx([
            ('POST', r'^https://oauth2\.googleapis\.com/token$', (200, {'access_token': 'GT'})),
            ('GET', base + r'/certificates/acme-www-example-test$',
             lambda c: (200, {'pemCertificate': self.have}) if self.have else
             (404, {'error': {'code': 404, 'message': 'not found'}})),
            ('POST', base + r'/certificates\?certificateId=acme-www-example-test$',
             (200, {'name': 'projects/proj-1/locations/global/operations/op1', 'done': False})),
            ('PATCH', base + r'/certificates/acme-www-example-test\?updateMask=selfManaged$',
             (200, {'name': 'projects/proj-1/locations/global/operations/op2', 'done': True})),
            ('GET', r'/operations/op1$', (200, {'name': 'x', 'done': True})),
        ])
        self.t = make('gcp_certmanager', {'service_account': json.dumps(self.sa)}, self.ctx)
        self.t._now = 1793534400
        self.t._sleep = lambda s: None

    def test_create_update_noop(self):
        a = FakeBundle('a')
        self.assertIn('made acme-www-example-test', self.t.deploy(a, {}))
        tok = urllib.parse.parse_qs(self.ctx.calls[0]['body'].decode())
        jwt = tok['assertion'][0].split('.')
        pad = lambda s: s + '=' * (-len(s) % 4)  # noqa: E731
        head = json.loads(base64.urlsafe_b64decode(pad(jwt[0])))
        claims = json.loads(base64.urlsafe_b64decode(pad(jwt[1])))
        self.assertEqual(head, {'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid1'})
        self.assertEqual(claims['iss'], self.sa['client_email'])
        self.assertEqual(claims['scope'], 'https://www.googleapis.com/auth/cloud-platform')
        self.assertEqual((claims['iat'], claims['exp']), (1793534400, 1793538000))
        # the signature is the key's
        d = tempfile.mkdtemp(dir=T.TMP)
        pub = subprocess.run(['openssl', 'pkey', '-pubout'], input=self.sa['private_key'].encode(),
                             capture_output=True, check=True).stdout
        with open(os.path.join(d, 'pub'), 'wb') as fh:
            fh.write(pub)
        with open(os.path.join(d, 'sig'), 'wb') as fh:
            fh.write(base64.urlsafe_b64decode(pad(jwt[2])))
        p = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', os.path.join(d, 'pub'),
                            '-signature', os.path.join(d, 'sig')],
                           input=('%s.%s' % (jwt[0], jwt[1])).encode(), capture_output=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        post = self.ctx.find('POST', r'certificateId=')[0]
        self.assertEqual(post['headers']['Authorization'], 'Bearer GT')
        body = json.loads(post['body'])
        self.assertEqual(body['selfManaged'], {'pemCertificate': a.fullchain_pem,
                                               'pemPrivateKey': a.key_pem})
        self.assertTrue(self.ctx.find('GET', r'/operations/op1$'))
        # there with the same certificate: nothing; with another: PATCH
        self.have = a.fullchain_pem
        self.assertTrue(self.t.deploy(a, {}).startswith('unchanged'))
        self.assertIn('updated', self.t.deploy(FakeBundle('b'), {}))
        self.assertEqual(len(self.ctx.find('PATCH', r'updateMask=selfManaged')), 1)

    def test_operation_error(self):
        self.ctx.routes.insert(0, ('GET', r'/operations/op1$', (200, {
            'done': True, 'error': {'code': 3, 'message': 'the key does not match'}})))
        with self.assertRaises(PluginError) as e:
            self.t.deploy(FakeBundle(), {})
        self.assertIn('the key does not match', str(e.exception))


class CloudflareSslTest(unittest.TestCase):
    def setUp(self):
        self.listed = [{'id': 'other', 'hosts': ['other.test']}]

        def post(call):
            self.listed.append({'id': 'cc1', 'hosts': ['www.example.test', 'example.test']})
            return 200, {'success': True, 'result': {'id': 'cc1'}}
        B = r'^https://api\.cloudflare\.com/client/v4'
        self.ctx = FakeCtx([
            ('GET', B + r'/zones\?name=example\.test$',
             (200, {'success': True, 'result': [{'id': 'a' * 32}]})),
            ('GET', B + r'/zones/a{32}/custom_certificates\?per_page=50$',
             lambda c: (200, {'success': True, 'result': self.listed})),
            ('POST', B + r'/zones/a{32}/custom_certificates$', post),
            ('PATCH', B + r'/zones/a{32}/custom_certificates/cc1$',
             (200, {'success': True, 'result': {'id': 'cc1'}})),
        ])
        self.t = make('cloudflare_ssl', {'token': 'CFT', 'zone': 'example.test'}, self.ctx)

    def test_upload_noop_replace(self):
        a = FakeBundle('a')
        self.assertIn('uploaded the custom certificate cc1', self.t.deploy(a, {}))
        post = self.ctx.find('POST', r'custom_certificates$')[0]
        self.assertEqual(post['headers']['Authorization'], 'Bearer CFT')
        body = json.loads(post['body'])
        self.assertEqual((body['certificate'], body['private_key'], body['bundle_method'],
                          body['type']), (a.fullchain_pem, a.key_pem, 'force', 'sni_custom'))
        self.assertTrue(self.t.deploy(a, {}).startswith('unchanged'))
        self.assertIn('replaced', self.t.deploy(FakeBundle('b'), {}))
        patch = json.loads(self.ctx.find('PATCH', r'cc1$')[0]['body'])
        self.assertNotIn('type', patch)
        # a new acme, no memory: found by its names
        t2 = make('cloudflare_ssl', {'token': 'CFT', 'zone': 'example.test'},
                  FakeCtx(self.ctx.routes))
        self.assertIn('replaced', t2.deploy(FakeBundle('a'), {}))

    def test_error_words(self):
        ctx = FakeCtx([('GET', r'/zones/a{32}$', (403, {'success': False, 'errors': [
            {'code': 9109, 'message': 'Unauthorized to access requested resource'}]}))])
        t = make('cloudflare_ssl', {'token': 'x', 'zone': 'a' * 32}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertIn('9109 Unauthorized', str(e.exception))
        self.assertFalse(e.exception.retry)


# ---------------------------------------------------------------------------
# VMware, server controllers
# ---------------------------------------------------------------------------
class VCenterTest(unittest.TestCase):
    def setUp(self):
        self.thumb = 'AA:BB'
        self.ctx = FakeCtx([
            ('POST', r'/api/session$', (201, '"sess-1"')),
            ('DELETE', r'/api/session$', (204, b'')),
            ('GET', r'/certificate-management/vcenter/tls$',
             lambda c: (200, {'thumbprint': self.thumb, 'subject_dn': 'CN=vc'})),
            ('POST', r'/certificate-management/vcenter/trusted-root-chains$', (201, '"chain-1"')),
            ('PUT', r'/certificate-management/vcenter/tls$', (204, b'')),
        ])
        self.t = make('vcenter', {'host': 'vc.example.test', 'user': 'administrator@vsphere.local',
                                  'password': 'pw'}, self.ctx)

    def test_replace_then_noop(self):
        a = FakeBundle()
        self.t.deploy(a, {})
        login = self.ctx.calls[0]
        self.assertEqual(login['headers']['Authorization'], 'Basic ' + base64.b64encode(
            b'administrator@vsphere.local:pw').decode())
        put = self.ctx.find('PUT', r'/tls$')[0]
        self.assertEqual(put['headers']['vmware-api-session-id'], 'sess-1')
        body = json.loads(put['body'])
        self.assertEqual((body['cert'], body['key']), (a.cert_pem, a.key_pem))
        self.assertEqual(body['root_cert'], a.chain_pems[0])        # the test CA is a root
        roots = json.loads(self.ctx.find('POST', r'trusted-root-chains')[0]['body'])
        self.assertEqual(roots, {'cert_chain': {'cert_chain': [a.chain_pems[0]]}})
        self.assertEqual(self.ctx.calls[-1]['method'], 'DELETE')
        self.thumb = ':'.join(re.findall('..', C.sha1_thumb(a)))
        self.assertTrue(self.t.deploy(a, {}).startswith('unchanged'))
        self.assertEqual(len(self.ctx.find('PUT', r'/tls$')), 1)

    def test_bad_login(self):
        ctx = FakeCtx([('POST', r'/api/session$', (401, {'error_type': 'UNAUTHENTICATED'}))])
        t = make('vcenter', {'host': 'vc', 'user': 'u', 'password': 'p'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertFalse(e.exception.retry)


class EsxiTest(unittest.TestCase):
    def test_write_restart_noop_rollback(self):
        a = FakeBundle()
        ssh = FakeSsh()
        t = make('esxi', {'host': 'esx1', 'user': 'root', 'auth': 'password', 'password': 'p'},
                 FakeCtx(ssh=ssh))
        t.deploy(a, {})
        self.assertEqual(len(ssh.puts), 2)
        self.assertEqual(ssh.puts[0][1], a.fullchain_pem.encode())
        script = [c for c, _ in ssh.runs if 'mv -f' in c][0]
        self.assertIn('/etc/vmware/ssl/rui.crt.acme-new', script)
        self.assertIn('chmod 400', script)
        self.assertTrue(any('/etc/init.d/hostd restart' in c for c, _ in ssh.runs))
        # the files there are these: nothing written
        ssh2 = FakeSsh([(r'sha256sum', (0, sums({'/etc/vmware/ssl/rui.crt': a.fullchain_pem.encode(),
                                                 '/etc/vmware/ssl/rui.key': a.key_pem.encode()}),
                                        ''))])
        t2 = make('esxi', {'host': 'esx1'}, FakeCtx(ssh=ssh2))
        self.assertTrue(t2.deploy(a, {}).startswith('unchanged'))
        self.assertEqual(ssh2.puts, [])
        # hostd does not come up: the old files back
        ssh3 = FakeSsh([(r'hostd restart', (1, '', 'hostd failed')),
                        (r'mv -f', (0, 'EXISTED 0\nEXISTED 1\n', ''))])
        t3 = make('esxi', {'host': 'esx1'}, FakeCtx(ssh=ssh3))
        with self.assertRaises(PluginError) as e:
            t3.deploy(a, {})
        self.assertIn('previous certificate is back', str(e.exception))
        self.assertTrue(any('rui.crt.acme-prev' in c and 'cp -p' in c and 'mv' not in c
                            for c, _ in ssh3.runs))


class RedfishTest(unittest.TestCase):
    def routes(self):
        return [
            ('GET', r'/redfish/v1/$', (200, {'RedfishVersion': '1.17.0',
                                             'Links': {'Sessions': {'@odata.id':
                                                       '/redfish/v1/SessionService/Sessions'}},
                                             'CertificateService': {'@odata.id':
                                                                    '/redfish/v1/CertificateService'}})),
            ('POST', r'/SessionService/Sessions$', (201, {}, {
                'X-Auth-Token': 'RFT', 'Location': '/redfish/v1/SessionService/Sessions/7'})),
            ('DELETE', r'/Sessions/7$', (204, b'')),
            ('GET', r'/redfish/v1/Managers$', (200, {'Members': [
                {'@odata.id': '/redfish/v1/Managers/iDRAC.Embedded.1'}]})),
            ('GET', r'/Managers/iDRAC\.Embedded\.1$', (200, {
                'Model': '16G', 'FirmwareVersion': '7.10', 'NetworkProtocol': {
                    '@odata.id': '/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol'}})),
            ('GET', r'/NetworkProtocol/HTTPS/Certificates$', (200, {'Members': [
                {'@odata.id': '/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/'
                              'Certificates/SecurityCertificate.1'}]})),
            ('POST', r'/CertificateService\.ReplaceCertificate$', (200, {})),
            ('POST', r'/Manager\.Reset$', (204, b'')),
        ]

    def test_replace_and_reset(self):
        ctx = FakeCtx(self.routes())
        t = make('redfish', {'host': 'idrac.test', 'user': 'root', 'password': 'calvin'}, ctx)
        t.served_now = lambda b: False
        a = FakeBundle()
        words = t.deploy(a, {'reset': True})
        self.assertIn('restarts', words)
        login = ctx.find('POST', r'/Sessions$')[0]
        self.assertEqual(json.loads(login['body']), {'UserName': 'root', 'Password': 'calvin'})
        rep = ctx.find('POST', r'ReplaceCertificate')[0]
        self.assertEqual(rep['headers']['X-Auth-Token'], 'RFT')
        self.assertEqual(rep['headers']['OData-Version'], '4.0')
        body = json.loads(rep['body'])
        self.assertEqual(body['CertificateType'], 'PEMchain')
        self.assertEqual(body['CertificateString'], a.key_pem + a.fullchain_pem)
        self.assertTrue(body['CertificateUri']['@odata.id'].endswith('SecurityCertificate.1'))
        self.assertEqual(json.loads(ctx.find('POST', r'Manager\.Reset')[0]['body']),
                         {'ResetType': 'GracefulRestart'})
        # served already: nothing asked
        t.served_now = lambda b: True
        n = len(ctx.calls)
        self.assertTrue(t.deploy(a, {}).startswith('unchanged'))
        self.assertEqual(len(ctx.calls), n)

    def test_pem_and_given_uri(self):
        ctx = FakeCtx(self.routes())
        t = make('redfish', {'host': 'bmc', 'user': 'u', 'password': 'p', 'basic_auth': True}, ctx)
        t.served_now = lambda b: False
        a = FakeBundle()
        t.deploy(a, {'cert_type': 'PEM', 'certificate_uri': '/redfish/v1/x/1'})
        rep = ctx.find('POST', r'ReplaceCertificate')[0]
        self.assertTrue(rep['headers']['Authorization'].startswith('Basic '))
        body = json.loads(rep['body'])
        self.assertEqual(body['CertificateString'], a.key_pem + a.cert_pem)
        self.assertEqual(body['CertificateUri'], {'@odata.id': '/redfish/v1/x/1'})
        self.assertFalse(ctx.find('POST', r'/Sessions$'))


# ---------------------------------------------------------------------------
# Firewalls, load balancers, NAC
# ---------------------------------------------------------------------------
class SophosTest(unittest.TestCase):
    def setUp(self):
        b = FakeBundle()
        self.prefix = C.name_prefix(b, {}, maxlen=50, serial_len=6)
        self.certs = [self.prefix + '20260101-aaaa01', self.prefix + '20260601-aaaa02', 'Other']
        self.reqs = []

        def api(call):
            p = parts_of(call)
            xml = p['reqxml'][1].decode()
            self.reqs.append((xml, p))
            login = '<Login><status>Authentication Successful</status></Login>'
            if '<Get><Certificate>' in xml:
                inner = ''.join('<Certificate><Name>%s</Name></Certificate>' % n
                                for n in self.certs)
            elif '<Get><FirewallRule>' in xml:
                inner = ('<FirewallRule transactionid=""><Name>WAF www</Name><HTTPBasedPolicy>'
                         '<Certificate>%s</Certificate></HTTPBasedPolicy></FirewallRule>'
                         % self.certs[1])
            elif 'UploadCertificate' in xml:
                self.certs.append(re.search(r'<Name>([^<]+)</Name></Certificate>|'
                                            r'<Action>UploadCertificate</Action><Name>([^<]+)',
                                            xml).group(2))
                inner = '<Certificate><Status code="200">Configuration applied successfully.' \
                        '</Status></Certificate>'
            elif '<Remove>' in xml:
                inner = '<Certificate><Status code="200">ok</Status></Certificate>'
            else:
                inner = '<FirewallRule><Status code="200">ok</Status></FirewallRule>'
            return 200, '<Response APIVersion="2000.1">%s%s</Response>' % (login, inner)
        self.ctx = FakeCtx([('POST', r'^https://fw\.test:4444/webconsole/APIController$', api)])
        self.t = make('sophos', {'host': 'fw.test', 'user': 'api', 'password': 'p<w'}, self.ctx)

    def test_upload_point_cleanup(self):
        a = FakeBundle()
        name = C.object_name(a, {}, maxlen=50, serial_len=6)
        self.t.deploy(a, {'rules': 'WAF www', 'keep': 1})
        up = [r for r in self.reqs if 'UploadCertificate' in r[0]][0]
        self.assertIn('<Username>api</Username><Password>p&lt;w</Password>', up[0])
        self.assertIn('<CertificateFormat>pkcs12</CertificateFormat>', up[0])
        self.assertIn('<CertificateFile>%s.p12</CertificateFile>' % name, up[0])
        fn, data = up[1]['file']
        self.assertEqual(fn, name + '.p12')
        pw = re.search(r'<Password>([^<]+)</Password></Certificate>', up[0]).group(1)
        self.assertIn(b'BEGIN CERTIFICATE', subprocess.run(
            ['openssl', 'pkcs12', '-nokeys', '-passin', 'pass:' + pw], input=data,
            capture_output=True).stdout)
        upd = [r[0] for r in self.reqs if '<Set operation="update">' in r[0]][0]
        self.assertIn('<Certificate>%s</Certificate>' % name, upd)
        self.assertNotIn('transactionid', upd)
        removed = [re.search(r'<Remove><Certificate><Name>([^<]+)', r[0]).group(1)
                   for r in self.reqs if '<Remove>' in r[0]]
        self.assertEqual(removed, [self.prefix + '20260101-aaaa01'])
        n = len(self.reqs)
        self.assertTrue(self.t.deploy(a, {'rules': 'WAF www', 'keep': 1}).startswith('unchanged'))
        self.assertEqual(len(self.reqs), n + 1)                 # only the listing

    def test_refused(self):
        ctx = FakeCtx([('POST', r'APIController', (200, '<Response><Login><status>'
                                                        'Authentication Failure</status></Login>'
                                                        '</Response>'))])
        t = make('sophos', {'host': 'fw', 'user': 'u', 'password': 'p'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertFalse(e.exception.retry)
        self.assertIn('Authentication Failure', str(e.exception))


class KempTest(unittest.TestCase):
    def test_add_bind_cleanup(self):
        a = FakeBundle()
        prefix = C.name_prefix(a, {}, maxlen=60)
        certs = [prefix + '20260101-aaaa0001', prefix + '20260601-aaaa0002']
        seen = []

        def access(call):
            d = json.loads(call['body'])
            seen.append(d)
            if d['cmd'] == 'listcert':
                return 200, {'code': 200, 'status': 'ok', 'cert': [{'name': n} for n in certs]}
            if d['cmd'] == 'addcert':
                certs.append(d['cert'])
            if d['cmd'] == 'addintermediate':
                return 422, {'code': 422, 'status': 'fail', 'message': 'already exists'}
            return 200, {'code': 200, 'status': 'ok'}
        ctx = FakeCtx([('POST', r'^https://lm\.test/accessv2$', access)])
        t = make('kemp', {'host': 'lm.test', 'apikey': 'K'}, ctx)
        t.deploy(a, {'virtual_services': '192.0.2.10:443\n192.0.2.11:8443:tcp'})
        add = [d for d in seen if d['cmd'] == 'addcert'][0]
        self.assertEqual(add['apikey'], 'K')
        self.assertEqual(add['replace'], 0)
        self.assertEqual(b64d(add['data']).decode(), a.fullchain_pem + a.key_pem)
        mods = [(d['vs'], d['port'], d['prot'], d['CertFile']) for d in seen if d['cmd'] == 'modvs']
        self.assertEqual(mods, [('192.0.2.10', '443', 'tcp', add['cert']),
                                ('192.0.2.11', '8443', 'tcp', add['cert'])])
        self.assertEqual([d['cert'] for d in seen if d['cmd'] == 'delcert'],
                         [prefix + '20260101-aaaa0001'])
        self.assertTrue(t.deploy(a, {'virtual_services': '192.0.2.10:443\n192.0.2.11:8443:tcp'})
                        .startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(a, {'virtual_services': 'nonsense', 'force': True})

    def test_password_and_error(self):
        ctx = FakeCtx([('POST', r'/accessv2$', (401, {'code': 401, 'status': 'fail',
                                                     'message': 'Unauthorized'}))])
        t = make('kemp', {'host': 'lm', 'auth': 'password', 'user': 'bal', 'password': 'x'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertFalse(e.exception.retry)
        d = json.loads(ctx.calls[0]['body'])
        self.assertEqual((d['apiuser'], d['apipass']), ('bal', 'x'))
        self.assertNotIn('apikey', d)


class CiscoIseTest(unittest.TestCase):
    def test_import_cleanup(self):
        a = FakeBundle()
        prefix = C.name_prefix(a, {}, maxlen=60)
        listed = [{'id': 'i1', 'friendlyName': prefix + '20260101-aaaa0001'},
                  {'id': 'i2', 'friendlyName': prefix + '20260601-aaaa0002'},
                  {'id': 'i3', 'friendlyName': 'Default self-signed server certificate'}]

        def imp(call):
            listed.append({'id': 'i9', 'friendlyName': json.loads(call['body'])['name']})
            return 200, {'response': {'id': 'i9', 'message': 'imported', 'status': 'SUCCESS'}}
        ctx = OpensslCtx([
            ('GET', r'/api/v1/certs/system-certificate/ise01\?size=100$',
             lambda c: (200, {'response': listed})),
            ('POST', r'/api/v1/certs/trusted-certificate/import$', (200, {})),
            ('POST', r'/api/v1/certs/system-certificate/import$', imp),
            ('DELETE', r'/api/v1/certs/system-certificate/ise01/i1$', (200, {})),
        ])
        t = make('cisco_ise', {'host': 'ise.test', 'user': 'ers', 'password': 'p',
                               'node': 'ise01'}, ctx)
        t.deploy(a, {'roles': 'eap\nportal'})
        call = ctx.find('POST', r'system-certificate/import$')[0]
        self.assertEqual(call['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'ers:p').decode())
        body = json.loads(call['body'])
        self.assertEqual(body['data'], a.cert_pem)
        self.assertTrue(body['eap'] and body['portal'])
        self.assertFalse(body['admin'] or body['pxgrid'] or body['saml'])
        self.assertEqual(body['portalGroupTag'], 'Default Portal Certificate Group')
        self.assertIn('ENCRYPTED PRIVATE KEY', body['privateKeyData'])
        self.assertTrue(body['password'])
        key = subprocess.run(['openssl', 'pkey', '-passin', 'pass:' + body['password']],
                             input=body['privateKeyData'].encode(), capture_output=True).stdout
        self.assertIn(b'PRIVATE KEY', key)
        trusted = json.loads(ctx.find('POST', r'trusted-certificate/import$')[0]['body'])
        self.assertEqual(trusted['data'], a.chain_pems[0])
        self.assertEqual(len(ctx.find('DELETE', r'')), 1)
        self.assertTrue(t.deploy(a, {'roles': 'eap\nportal'}).startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(a, {'roles': 'eap\nwifi', 'force': True})


# ---------------------------------------------------------------------------
# Proxies and web servers
# ---------------------------------------------------------------------------
class HaproxyTest(unittest.TestCase):
    PATH = '/etc/haproxy/certs/site.pem'

    def test_swap_then_noop(self):
        a = FakeBundle()
        ssh = FakeSsh([
            (r"show ssl cert[^/]*\| socat", (0, '# filename\n%s\n' % self.PATH, '')),
            (r"set ssl cert", (0, 'Transaction created for certificate %s!\n' % self.PATH, '')),
            (r"commit ssl cert", (0, 'Committing %s\nSuccess!\n' % self.PATH, '')),
        ])
        t = make('haproxy', {'host': 'lb1'}, FakeCtx(ssh=ssh))
        words = t.deploy(a, {'cert_path': self.PATH})
        self.assertIn('swapped', words)
        self.assertEqual(ssh.puts[0][1], (a.key_pem + a.fullchain_pem).encode())
        setc = [c for c, _ in ssh.runs if 'set ssl cert' in c][0]
        self.assertIn('UNIX-CONNECT:/run/haproxy/admin.sock', setc)
        self.assertIn('cat /tmp/.acme-haproxy-', setc)
        # the script the shell gets: the payload's lines
        inner = re.match(r"sh -c (.*)$", setc, re.S).group(1)
        script = subprocess.run(['sh', '-c', 'printf %s ' + inner], capture_output=True,
                                text=True).stdout
        tmpfile = os.path.join(T.TMP, 'payload')
        with open(tmpfile, 'w') as fh:
            fh.write('PEM\n')
        demo = re.sub(r'cat \S+;', 'cat %s;' % tmpfile, script).replace(
            '| socat stdio UNIX-CONNECT:/run/haproxy/admin.sock', '')
        out = subprocess.run(['sh', '-c', demo], capture_output=True, text=True).stdout
        self.assertEqual(out, 'set ssl cert %s <<\nPEM\n\n' % self.PATH)
        self.assertTrue(any("commit ssl cert %s" % self.PATH in c for c, _ in ssh.runs))
        # the file holds it and HAProxy serves its serial: nothing to do
        serial = a.serial.upper()
        ssh2 = FakeSsh([(r'sha256sum', (0, sums({self.PATH: (a.key_pem + a.fullchain_pem)
                                                 .encode()}), '')),
                        (r"show ssl cert /", (0, 'Filename: %s\nSerial: %s\n' % (self.PATH, serial),
                                              ''))])
        t2 = make('haproxy', {'host': 'lb1'}, FakeCtx(ssh=ssh2))
        self.assertTrue(t2.deploy(a, {'cert_path': self.PATH}).startswith('unchanged'))
        self.assertEqual(ssh2.puts, [])

    def test_unknown_needs_crt_list(self):
        ssh = FakeSsh([(r"show ssl cert[^/]*\| socat", (0, '# filename\n', '')),
                       (r"new ssl cert", (0, 'New empty certificate store!\n', '')),
                       (r"set ssl cert", (0, 'Transaction created\n', '')),
                       (r"commit ssl cert|add ssl crt-list", (0, 'Success!\n', ''))])
        t = make('haproxy', {'host': 'lb1'}, FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'cert_path': self.PATH})
        self.assertFalse(e.exception.retry)
        self.assertIn('new', t.deploy(FakeBundle(), {'cert_path': self.PATH,
                                                     'crt_list': '/etc/haproxy/list.txt'}))
        self.assertTrue(any('add ssl crt-list /etc/haproxy/list.txt %s' % self.PATH in c
                            for c, _ in ssh.runs))
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {'cert_path': '/x; rm -rf /'})


class TraefikTest(unittest.TestCase):
    def test_files_for_real(self):
        d = tempfile.mkdtemp(dir=T.TMP)
        ssh = FakeSsh(local=True)
        t = make('traefik', {'host': 'proxy'}, FakeCtx(ssh=ssh))
        a = FakeBundle()
        prefix = C.name_prefix(a, {})
        cdir, ddir = os.path.join(d, 'certs'), os.path.join(d, 'dyn')
        os.makedirs(cdir)
        for old in ('20260101-aaaa0001', '20260601-aaaa0002'):
            for ext in ('crt', 'key'):
                open(os.path.join(cdir, '%s%s.%s' % (prefix, old, ext)), 'w').close()
        opts = {'cert_dir': cdir, 'dynamic_dir': ddir, 'seen_as': '/certs', 'default_cert': True,
                'keep': 1}
        t.deploy(a, opts)
        name = C.object_name(a, {})
        self.assertEqual(read(os.path.join(cdir, name + '.crt')), a.fullchain_pem)
        self.assertEqual(os.stat(os.path.join(cdir, name + '.key')).st_mode & 0o777, 0o600)
        yml = read(os.path.join(ddir, prefix.rstrip('-') + '.yml'))
        self.assertIn('    - certFile: /certs/%s.crt\n      keyFile: /certs/%s.key' % (name, name),
                      yml)
        self.assertIn('defaultCertificate:', yml)
        left = sorted(os.listdir(cdir))
        self.assertNotIn(prefix + '20260101-aaaa0001.crt', left)
        self.assertIn(prefix + '20260601-aaaa0002.crt', left)
        self.assertFalse([f for f in os.listdir(cdir) if 'acme-prev' in f or 'acme-new' in f])
        self.assertTrue(t.deploy(a, opts).startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(a, dict(opts, cert_dir='/etc/../x'))


class CaddyTest(unittest.TestCase):
    def test_api(self):
        a = FakeBundle()
        state = {'load_pem': [{'certificate': 'OTHER', 'key': 'K', 'tags': ['mine']},
                              {'certificate': 'OLD', 'key': 'K', 'tags': ['acme-www.example.test']}]}
        sent = []

        def curl(cmd, inp):
            if '-X GET' in cmd:
                return 0, json.dumps(state) + '\n200', ''
            sent.append(cmd)
            return 0, '\n200', ''
        ssh = FakeSsh([(r'curl ', curl)])
        t = make('caddy', {'host': 'web1'}, FakeCtx(ssh=ssh))
        t.deploy(a, {})
        self.assertIn('-X PATCH', sent[0])
        self.assertIn('http://localhost:2019/config/apps/tls/certificates/load_pem', sent[0])
        new = json.loads(ssh.puts[0][1])
        self.assertEqual([e['tags'] for e in new], [['mine'], ['acme-www.example.test']])
        self.assertEqual((new[1]['certificate'], new[1]['key']), (a.fullchain_pem, a.key_pem))
        state['load_pem'] = new
        self.assertTrue(t.deploy(a, {}).startswith('unchanged'))

    def test_api_error_and_files(self):
        ssh = FakeSsh([(r'curl ', (0, '{"error":"loading new config: bad"}\n400', ''))])
        t = make('caddy', {'host': 'web1'}, FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('Caddy said 400 - loading new config: bad', str(e.exception))
        ssh = FakeSsh()
        t = make('caddy', {'host': 'web1'}, FakeCtx(ssh=ssh))
        t.deploy(FakeBundle(), {'mode': 'files', 'cert_file': '/etc/caddy/certs/{name}.crt',
                                'key_file': '/etc/caddy/certs/{name}.key'})
        script = [c for c, _ in ssh.runs if 'mv -f' in c][0]
        self.assertIn('/etc/caddy/certs/www.example.test.key.acme-new', script)
        self.assertIn('chown caddy:caddy', script)
        self.assertTrue(any('caddy reload --config /etc/caddy/Caddyfile' in c
                            for c, _ in ssh.runs))


class NginxUnitTest(unittest.TestCase):
    def test_upload_point_cleanup(self):
        a = FakeBundle()
        prefix = C.name_prefix(a, {})
        name = C.object_name(a, {})
        certs = {prefix + '20260101-aaaa0001': {}, prefix + '20260601-aaaa0002': {}}
        listeners = {'*:443': {'pass': 'routes', 'tls': {'certificate':
                                                          prefix + '20260601-aaaa0002'}},
                     '*:8443': {'pass': 'routes', 'tls': {'certificate': ['other', prefix +
                                                                         '20260601-aaaa0002']}}}
        done = []

        def curl(cmd, inp):
            if '-X GET' in cmd and cmd.rstrip("'").endswith('/certificates'):
                return 0, json.dumps(certs) + '\n200', ''
            if '-X GET' in cmd:
                return 0, json.dumps(listeners) + '\n200', ''
            done.append(cmd)
            return 0, '{"success": "Reconfiguration done."}\n200', ''
        ssh = FakeSsh([(r'curl ', curl)])
        t = make('nginx_unit', {'host': 'app1'}, FakeCtx(ssh=ssh))
        t.deploy(a, {'listeners': '*:443\n*:8443'})
        self.assertIn('--unix-socket /var/run/control.unit.sock', done[0])
        self.assertIn('http://localhost/certificates/%s' % name, done[0])
        self.assertEqual(ssh.puts[0][1], (a.fullchain_pem + a.key_pem).encode())
        self.assertIn('http://localhost/config/listeners/%2A%3A443/tls/certificate', done[1])
        self.assertEqual(json.loads(ssh.puts[1][1]), name)
        self.assertEqual(json.loads(ssh.puts[2][1]), ['other', name])
        self.assertTrue(any('-X DELETE' in c and '20260101-aaaa0001' in c for c in done))
        self.assertFalse(any('-X DELETE' in c and '20260601-aaaa0002' in c for c in done))
        certs[name] = {}
        listeners['*:443']['tls']['certificate'] = name
        listeners['*:8443']['tls']['certificate'] = ['other', name]
        self.assertTrue(t.deploy(a, {'listeners': '*:443\n*:8443'}).startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(a, {'listeners': '*:9443', 'force': True})


# ---------------------------------------------------------------------------
# Appliances and platforms over SSH
# ---------------------------------------------------------------------------
class ZimbraTest(unittest.TestCase):
    def test_deploy_and_refused(self):
        a = FakeBundle()
        ssh = FakeSsh([(r'verifycrt', (0, '** Valid certificate chain: /opt/zimbra/ssl/acme/'
                                          'cert.pem: OK', ''))])
        t = make('zimbra', {'host': 'mail'}, FakeCtx(ssh=ssh))
        t.deploy(a, {'restart': 'zmcontrol'})
        cmds = [c for c, _ in ssh.runs]
        v = [c for c in cmds if 'verifycrt' in c][0]
        self.assertIn('su - zimbra -c', v)
        self.assertIn('zmcertmgr verifycrt comm /opt/zimbra/ssl/zimbra/commercial/commercial.key '
                      '/opt/zimbra/ssl/acme/cert.pem /opt/zimbra/ssl/acme/chain.pem', v)
        self.assertTrue(any('deploycrt comm' in c for c in cmds))
        self.assertTrue(any('zmcontrol restart' in c for c in cmds))
        chain = [d for p, d, m in ssh.puts]
        self.assertIn(a.chain_pems[0].encode(), chain)               # the root (self-signed)
        # zmcertmgr says no: the old key back, no deploycrt
        ssh2 = FakeSsh([(r'verifycrt', (1, 'ERROR: Unable to validate certificate chain', '')),
                        (r'mv -f', (0, 'EXISTED 0\n', ''))])
        t2 = make('zimbra', {'host': 'mail'}, FakeCtx(ssh=ssh2))
        with self.assertRaises(PluginError) as e:
            t2.deploy(a, {})
        self.assertIn('previous key is back', str(e.exception))
        self.assertFalse(any('deploycrt' in c for c, _ in ssh2.runs))

    def test_needs_root(self):
        b = FakeBundle()
        b.chain_pems = []
        with self.assertRaises(PluginError) as e:
            make('zimbra', {'host': 'mail'}, FakeCtx()).deploy(b, {})
        self.assertIn('root', str(e.exception))


class TrueNasTest(unittest.TestCase):
    def test_import_ui_cleanup(self):
        a = FakeBundle()
        from acmelib.plugins.targets.truenas import tn_name
        name = tn_name(C.object_name(a, {}))
        prefix = tn_name(C.name_prefix(a, {}))
        certs = [{'id': 1, 'name': prefix + '20260101-aaaa0001'},
                 {'id': 2, 'name': prefix + '20260601-aaaa0002'},
                 {'id': 3, 'name': 'truenas_default'}]
        ui = {'id': 2}

        def midclt(cmd, inp):
            if 'certificate.query' in cmd:
                return 0, json.dumps(certs), ''
            if 'system.general.config' in cmd:
                return 0, json.dumps({'ui_certificate': ui}), ''
            if 'certificate.create' in cmd:
                certs.append({'id': 9, 'name': name})
                return 0, 'Status: ok\n{"id": 9}', ''
            if 'system.general.update' in cmd:
                ui['id'] = 9
            return 0, 'null', ''
        ssh = FakeSsh([(r'midclt', midclt)])
        t = make('truenas', {'host': 'nas'}, FakeCtx(ssh=ssh))
        self.assertIn('web interface', t.deploy(a, {'ftp': True}))
        cmds = [c for c, _ in ssh.runs]
        self.assertTrue(any('midclt call -j certificate.create' in c and '$(cat /tmp/.acme-truenas-'
                            in c for c in cmds))
        body = json.loads(ssh.puts[0][1])
        self.assertEqual(body['create_type'], 'CERTIFICATE_CREATE_IMPORTED')
        self.assertEqual((body['certificate'], body['privatekey']), (a.fullchain_pem, a.key_pem))
        self.assertNotIn('.', body['name'])
        self.assertTrue(any('system.general.update' in c and '"ui_certificate": 9' in c
                            for c in cmds))
        self.assertTrue(any('system.general.ui_restart' in c for c in cmds))
        self.assertTrue(any('ftp.update' in c and '"ssltls_certificate": 9' in c for c in cmds))
        self.assertTrue(any('certificate.delete 1' in c for c in cmds))
        self.assertFalse(any('certificate.delete 2' in c or 'certificate.delete 3' in c
                             for c in cmds))
        n = len(ssh.puts)
        self.assertTrue(t.deploy(a, {'ftp': True}).startswith('unchanged'))
        self.assertEqual(len(ssh.puts), n)

    def test_midclt_error(self):
        ssh = FakeSsh([(r'midclt', (1, '', '[ENOMETHOD] Method "x" not found'))])
        with self.assertRaises(PluginError) as e:
            make('truenas', {'host': 'nas'}, FakeCtx(ssh=ssh)).test()
        self.assertIn('ENOMETHOD', str(e.exception))


class DockerSwarmTest(unittest.TestCase):
    def test_rotate(self):
        a = FakeBundle()
        prefix = C.name_prefix(a, {}, maxlen=58)
        name = C.object_name(a, {}, maxlen=58)
        old1, old2 = prefix + '20260101-aaaa0001', prefix + '20260601-aaaa0002'
        secrets = [old1 + '.crt', old1 + '.key', old2 + '.crt', old2 + '.key', 'db_password']
        mounts = [{'SecretName': old2 + '.crt', 'File': {'Name': 'tls.crt'}},
                  {'SecretName': old2 + '.key', 'File': {'Name': 'tls.key'}},
                  {'SecretName': 'db_password', 'File': {'Name': 'db'}}]

        def answer(cmd, inp):
            if 'secret ls' in cmd:
                return 0, '\n'.join(secrets), ''
            if 'service inspect' in cmd:
                return 0, json.dumps(mounts), ''
            m = re.search(r'secret create --label managed-by=acme (\S+)', cmd)
            if m:
                secrets.append(m.group(1))
            return 0, '', ''
        ssh = FakeSsh([(r'docker', answer)])
        t = make('docker_swarm', {'host': 'mgr1'}, FakeCtx(ssh=ssh))
        t.deploy(a, {'services': 'web_proxy'})
        cmds = [c for c, _ in ssh.runs]
        self.assertTrue(any('secret create --label managed-by=acme %s.crt' % name in c
                            for c in cmds))
        self.assertEqual(ssh.puts[0][1], a.fullchain_pem.encode())
        self.assertEqual(ssh.puts[1][1], a.key_pem.encode())
        upd = [c for c in cmds if 'service update' in c][0]
        self.assertIn('--secret-rm %s.crt' % old2, upd)
        self.assertIn('--secret-add source=%s.crt,target=tls.crt,mode=0444' % name, upd)
        self.assertIn('--secret-add source=%s.key,target=tls.key,mode=0400' % name, upd)
        self.assertNotIn('db_password', upd)
        self.assertTrue(upd.rstrip("'").endswith('web_proxy'))
        rms = [c for c in cmds if 'secret rm' in c]
        self.assertEqual(len(rms), 2)
        self.assertTrue(all(old1 in c for c in rms))
        mounts[:2] = [{'SecretName': name + '.crt', 'File': {'Name': 'tls.crt'}},
                      {'SecretName': name + '.key', 'File': {'Name': 'tls.key'}}]
        self.assertTrue(t.deploy(a, {'services': 'web_proxy'}).startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(a, {'services': 'web;rm -rf /', 'force': True})


class StrongswanTest(unittest.TestCase):
    def test_files_for_real(self):
        d = tempfile.mkdtemp(dir=T.TMP)
        bindir = os.path.join(d, 'bin')
        os.makedirs(bindir)
        log = os.path.join(d, 'log')
        with open(os.path.join(bindir, 'swanctl'), 'w') as fh:
            fh.write('#!/bin/sh\necho "$@" >> %s\n' % log)
        os.chmod(os.path.join(bindir, 'swanctl'), 0o755)
        old_path = os.environ['PATH']
        os.environ['PATH'] = bindir + ':' + old_path
        try:
            t = make('strongswan', {'host': 'vpn'}, FakeCtx(ssh=FakeSsh(local=True)))
            a = FakeBundle()
            words = t.deploy(a, {'dir': os.path.join(d, 'swanctl')})
            self.assertIn('swanctl --load-creds', words)
            self.assertEqual(read(os.path.join(d, 'swanctl', 'x509', 'www.example.test.crt')),
                             a.cert_pem)
            key = os.path.join(d, 'swanctl', 'private', 'www.example.test.key')
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            ca = os.listdir(os.path.join(d, 'swanctl', 'x509ca'))
            self.assertEqual(ca, ['acme-ca-%s.crt' % C.chain_id(a.chain_pems[0])])
            self.assertEqual(read(log), '--load-creds\n')
            self.assertTrue(t.deploy(a, {'dir': os.path.join(d, 'swanctl')})
                            .startswith('unchanged'))
            self.assertEqual(read(log), '--load-creds\n')
        finally:
            os.environ['PATH'] = old_path


# ---------------------------------------------------------------------------
# Small boxes
# ---------------------------------------------------------------------------
class FritzBoxTest(unittest.TestCase):
    def test_responses(self):
        from acmelib.plugins.targets.fritzbox import pbkdf2_response, md5_response
        # the examples of AVM's technical note "Session ID" (2021-05-03)
        self.assertEqual(pbkdf2_response('2$10000$5A1711$2000$5A1722', '1example!'),
                         '5A1722$1798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb')
        self.assertEqual(md5_response('1234567z', 'äbc'), '1234567z-9e224a41eeefa284df7bb0f26c2913e2')

    def test_upload(self):
        sid = 'abcdef0123456789'

        def login(call):
            q = urllib.parse.parse_qs(call['body'].decode())
            if q.get('username') == ['acme'] and q['response'][0].startswith('5A1722$'):
                return 200, '<SessionInfo><SID>%s</SID></SessionInfo>' % sid
            return 200, '<SessionInfo><SID>0000000000000000</SID><BlockTime>8</BlockTime>' \
                        '</SessionInfo>'

        def upload(call):
            p = parts_of(call)
            self.assertEqual(p['sid'][1].decode(), sid)
            self.assertEqual(p['BoxCertPassword'][1], b'')
            self.assertEqual(p['BoxCertImportFile'][0], 'BoxCert.pem')
            self.got = p['BoxCertImportFile'][1]
            return 200, '<html><body><p>Das SSL-Zertifikat wurde erfolgreich importiert.</p>'
        routes = [
            ('GET', r'/login_sid\.lua\?version=2$', (200, '<SessionInfo><SID>0000000000000000'
                                                         '</SID><Challenge>2$10000$5A1711$2000'
                                                         '$5A1722</Challenge></SessionInfo>')),
            ('POST', r'/login_sid\.lua\?version=2$', login),
            ('POST', r'/cgi-bin/firmwarecfg$', upload),
            ('GET', r'logout=1', (200, '<SessionInfo><SID>0000000000000000</SID></SessionInfo>')),
        ]
        ctx = FakeCtx(routes)
        t = make('fritzbox', {'host': 'fritz.box', 'user': 'acme', 'password': '1example!'}, ctx)
        t.served_now = lambda b: False
        a = FakeBundle()
        self.assertIn('uploaded', t.deploy(a, {}))
        self.assertEqual(self.got, (a.key_pem + a.fullchain_pem).encode())
        self.assertTrue(ctx.find('GET', r'logout=1&sid=' + sid))
        bad = make('fritzbox', {'host': 'fritz.box', 'user': 'x', 'password': 'y'}, FakeCtx(routes))
        with self.assertRaises(PluginError) as e:
            bad.test()
        self.assertFalse(e.exception.retry)
        self.assertIn('blocks sign-ins for 8 s', str(e.exception))
        refused = list(routes)
        refused[2] = ('POST', r'/cgi-bin/firmwarecfg$',
                      (200, '<html>Fehler: Das SSL-Zertifikat ist ungültig.</html>'))
        t3 = make('fritzbox', {'host': 'fritz.box', 'user': 'acme', 'password': '1example!'},
                  FakeCtx(refused))
        t3.served_now = lambda b: False
        with self.assertRaises(PluginError):
            t3.deploy(a, {})


class UnifiOsTest(unittest.TestCase):
    def test_add_activate_cleanup(self):
        a = FakeBundle()
        prefix = C.name_prefix(a, {})
        listed = [{'id': 'u1', 'name': prefix + '20260101-aaaa0001', 'fingerprint': 'AA'},
                  {'id': 'u2', 'name': prefix + '20260601-aaaa0002', 'fingerprint': 'BB'}]
        jwt = 'x.%s.y' % base64.urlsafe_b64encode(json.dumps(
            {'csrfToken': 'CSRF1'}).encode()).decode().rstrip('=')

        def add(call):
            b = json.loads(call['body'])
            listed.append({'id': 'u9', 'name': b['name'],
                           'fingerprint': ':'.join(re.findall('..', C.sha1_thumb(a)))})
            return 200, {'id': 'u9'}
        ctx = FakeCtx([
            ('POST', r'/api/auth/login$', (200, {'username': 'acme'},
                                           {'Set-Cookie': 'TOKEN=%s; path=/; HttpOnly' % jwt})),
            ('GET', r'/api/userCertificates$', lambda c: (200, listed)),
            ('POST', r'/api/userCertificates$', add),
            ('PUT', r'/api/userCertificates/u9/status$', (200, {})),
            ('DELETE', r'/api/userCertificates/u1$', (200, {})),
        ])
        t = make('unifi_os', {'host': 'udm.test', 'user': 'acme', 'password': 'p'}, ctx)
        t.deploy(a, {})
        login = json.loads(ctx.calls[0]['body'])
        self.assertEqual(login, {'username': 'acme', 'password': 'p', 'token': '',
                                 'rememberMe': False})
        post = ctx.find('POST', r'/api/userCertificates$')[0]
        self.assertEqual(post['headers']['Cookie'], 'TOKEN=' + jwt)
        self.assertEqual(post['headers']['X-CSRF-Token'], 'CSRF1')
        body = json.loads(post['body'])
        self.assertEqual((body['cert'], body['key']), (a.fullchain_pem, a.key_pem))
        self.assertEqual(json.loads(ctx.find('PUT', r'/status$')[0]['body']), {'active': True})
        self.assertEqual(len(ctx.find('DELETE', r'')), 1)
        self.assertTrue(t.deploy(a, {}).startswith('unchanged'))
        self.assertEqual(len(ctx.find('POST', r'/api/userCertificates$')), 1)


# ---------------------------------------------------------------------------
class DescribeTest(unittest.TestCase):
    def test_every_new_module(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        kinds = reg.all('target')
        for k in NEW_KINDS:
            self.assertIn(k, kinds)
            d = kinds[k].describe()
            json.dumps(d)
            self.assertTrue(d['title'] and d['vendor'] and d['description'], k)
            self.assertEqual(d['doc'], 'targets.md', k)
            for f in d['fields'] + d['deploy_fields']:
                self.assertIn(f['type'], FIELD_TYPES, (k, f['key']))
            src = read(kinds[k]._module_file)
            self.assertIn('https://', src.split('"""')[1], '%s cites no source' % k)

    def test_docs_and_czech(self):
        root = os.path.dirname(HERE)
        docs = read(os.path.join(root, 'docs', 'targets.md'))
        readme = read(os.path.join(root, 'README.md'))
        cs = json.loads(read(os.path.join(root, 'web', 'lang', 'cs.json')))
        sources = {v['source'] for v in cs['strings'].values()}
        reg = Registry(extra_dirs=[]).reload()

        def words_of(d):
            out = [d['title'], d['description']]
            for f in d['fields'] + d['deploy_fields']:
                out += [f['label'], f.get('help', '')]
                out += [o[1] for o in f.get('options') or []]
            return [w for w in out if w]
        # the fields every module shares (ssh_fields, tls_fields...) are the older modules'
        shared = set()
        for k, cls in reg.all('target').items():
            if k not in NEW_KINDS:
                shared.update(words_of(cls.describe()))
        missing = []
        for k in NEW_KINDS:
            self.assertIn('## `%s`' % k, docs)
            self.assertIn('| `%s` |' % k, docs)
            d = reg.get('target', k).describe()
            self.assertIn(d['title'].split(' (')[0].lower(), readme.lower(), k)
            missing += ['%s: %s' % (k, w) for w in words_of(d)
                        if w not in sources and w not in shared]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
