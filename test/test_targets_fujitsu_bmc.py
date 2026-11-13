#!/usr/bin/env python3
"""Fujitsu and server management controllers (BMC), without a network.

    python3 test/test_targets_fujitsu_bmc.py

  irmc            Fujitsu iRMC S4/S5/S6: SCCI over /config (fsas.primergy irmc_certificate),
                  the reset /rest/v1/Oem/iRMC/Reset (role irmc_set_certificate) or Redfish
  supermicro_bmc  Supermicro X12-X14: Redfish OEM SmcSSLCert.Upload (cert_file, key_file)
  cisco_imc       Cisco IMC: XML API /nuova, External Certificate + key, activate
  huawei_ibmc     Huawei / xFusion iBMC: /tmp/web upload, HttpsCert.ImportCustomCertificate
  fujitsu_ism     ISM-VA: FTP into /Administrator/ftp, ismadm sslcert set, ismadm power restart
  eternus_dx      ETERNUS DX/AF: FTP(S) staging, CLI import ssl-certificate over SSH

A fake HTTP(S) answers as each vendor documents; a fake FTP server and the fake SSH session
of test_targets.py record what is sent. Each test asserts the exact calls (method, path,
body), the error paths and that nothing is changed where it must not be.
"""
import json
import os
import re
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make, read  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

KINDS = ('irmc', 'supermicro_bmc', 'cisco_imc', 'huawei_ibmc', 'fujitsu_ism', 'eternus_dx')


def setUpModule():
    T.setUpModule()
    j = lambda n: os.path.join(T.TMP, n)  # noqa: E731
    # an RSA leaf (the iRMC, the IMC and ETERNUS take RSA only), its key PKCS#1
    subprocess.run(['openssl', 'genrsa', '-traditional', '-out', j('r.key'), '2048'],
                   capture_output=True, check=True)
    subprocess.run(['openssl', 'req', '-new', '-key', j('r.key'), '-out', j('r.csr'),
                    '-subj', '/CN=www.example.test'], capture_output=True, check=True)
    subprocess.run(['openssl', 'x509', '-req', '-in', j('r.csr'), '-CA', j('ca.crt'),
                    '-CAkey', j('ca.key'), '-CAcreateserial', '-days', '10', '-out', j('r.crt'),
                    '-extfile', j('ext')], capture_output=True, check=True)
    T.CERTS['r'] = (j('r.crt'), j('r.key'))


def tearDownModule():
    T.tearDownModule()


def rsa():
    b = FakeBundle('r')
    b.key_type = 'rsa2048'
    return b


def multipart_parts(call):
    ctype = call['headers'].get('Content-Type', '')
    boundary = ctype.split('boundary=')[1].encode()
    out = {}
    for part in call['body'].split(b'--' + boundary):
        if b'Content-Disposition' not in part:
            continue
        head, _, data = part.partition(b'\r\n\r\n')
        name = re.search(rb'name="([^"]+)"', head).group(1).decode()
        fn = re.search(rb'filename="([^"]+)"', head)
        out[name] = (fn.group(1).decode() if fn else None, data[:-2])
    return out


class FakeFtp(object):
    """ftplib.FTP / FTP_TLS as the modules use them; every command recorded."""
    log = []
    files = {}
    refuse_login = False

    def __init__(self, context=None, timeout=None):
        self.tls = context is not None
        FakeFtp.log.append(('new', 'tls' if self.tls else 'plain'))

    def connect(self, host, port):
        FakeFtp.log.append(('connect', host, port))

    def login(self, user, password):
        import ftplib
        if FakeFtp.refuse_login:
            raise ftplib.error_perm('530 Login incorrect.')
        FakeFtp.log.append(('login', user, password))

    def prot_p(self):
        FakeFtp.log.append(('prot_p',))

    def set_pasv(self, v):
        FakeFtp.log.append(('pasv', v))

    def nlst(self, folder):
        FakeFtp.log.append(('nlst', folder))
        return [k for k in FakeFtp.files if k.startswith(folder)]

    def storbinary(self, cmd, fh):
        path = cmd.split(' ', 1)[1]
        FakeFtp.files[path] = fh.read()
        FakeFtp.log.append(('stor', path))

    def delete(self, path):
        FakeFtp.files.pop(path, None)
        FakeFtp.log.append(('dele', path))

    def quit(self):
        FakeFtp.log.append(('quit',))

    def close(self):
        pass

    @classmethod
    def reset(cls):
        cls.log, cls.files, cls.refuse_login = [], {}, False


def with_ftp(t):
    t.FTP = FakeFtp
    t.FTP_TLS = FakeFtp
    return t


def refuse_crt():
    """FakeFtp.storbinary refusing the certificate (after the key went up); the original."""
    import ftplib
    orig = FakeFtp.storbinary

    def stor(self_, cmd, fh):
        if cmd.endswith('.crt'):
            raise ftplib.error_perm('552 Quota exceeded')
        return orig(self_, cmd, fh)
    FakeFtp.storbinary = stor
    return orig


def expire_once():
    """FakeFtp.delete answering 421 (the server closed the idle session) once; the original."""
    import ftplib
    orig = FakeFtp.delete
    gone = [True]

    def dele(self_, path):
        if gone[0]:
            gone[0] = False
            FakeFtp.log.append(('421', path))
            raise ftplib.error_temp('421 Timeout.')
        return orig(self_, path)
    FakeFtp.delete = dele
    return orig


def not_served(t):
    t.served_now = lambda b: False
    return t


class RegisteredTest(unittest.TestCase):
    def test_every_kind_is_there_plain(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        for k in KINDS:
            vers = reg.versions_of('target', k)
            self.assertEqual(sorted(vers), [''], k)
            cls = vers['']
            self.assertTrue(cls.title and cls.vendor and cls.description, k)
            self.assertIsNotNone(cls.served_wait, k)

    def test_guides_both_languages(self):
        d = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for k in KINDS:
            for suffix in ('.md', '.cs.md'):
                md = read(os.path.join(d, k + suffix))
                self.assertTrue(md.startswith('# '), k + suffix)
                self.assertIn('```', md, k + suffix)
                self.assertIn('openssl s_client', md, k + suffix)
            self.assertIn('Vyplnění v acme', read(os.path.join(d, k + '.cs.md')), k)
            self.assertIn('Fill in acme', read(os.path.join(d, k + '.md')), k)


# ---------------------------------------------------------------------------
SCCI_OK = ('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><Status><Value>0</Value>'
           '<Severity>Information</Severity><Message>No Error</Message></Status>')


def scci_answer(call):
    body = call['body'].decode()
    if 'OC="E001"' in body:
        return (200, '<?xml version="1.0"?><CMDSEQ><CMD Context="SCCI" OC="E001" OE="1982" '
                     'OI="0" Type="GET"><DATA Type="xsd::string">-----BEGIN CERTIFICATE-----'
                     '\nMIIB\n-----END CERTIFICATE-----</DATA><STATUS>0</STATUS></CMD></CMDSEQ>')
    return (200, SCCI_OK)


class IrmcTest(unittest.TestCase):
    def routes(self, scci=scci_answer):
        return [('POST', r'/config$', scci),
                ('POST', r'/rest/v1/Oem/iRMC/Reset$', (202, b'')),
                ('POST', r'/redfish/v1/Managers/iRMC/Actions/Manager\.Reset$', (204, b''))]

    def make(self, ctx):
        return not_served(make('irmc', {'host': 'irmc.test', 'user': 'svc-cert',
                                         'password': 'pw'}, ctx))

    def test_deploy_scci_then_reset(self):
        ctx = FakeCtx(self.routes())
        b = rsa()
        words = self.make(ctx).deploy(b, {})
        self.assertIn('the iRMC resets', words)
        self.assertEqual([(c['method'], c['path']) for c in ctx.calls],
                         [('POST', '/config'), ('POST', '/rest/v1/Oem/iRMC/Reset')])
        call = ctx.calls[0]
        self.assertTrue(call['headers']['Authorization'].startswith('Basic '))
        root = ET.fromstring(call['body'])
        cmds = root.findall('CMD')
        self.assertEqual([(c.get('OC'), c.get('OE'), c.get('Type'), c.get('CA')) for c in cmds],
                         [('E002', '1981', 'SET', '-1'), ('E002', '1982', 'SET', '-1'),
                          ('E002', '1983', 'SET', '-1')])
        self.assertIn('BEGIN RSA PRIVATE KEY', cmds[0].find('DATA').text)
        self.assertEqual(cmds[1].find('DATA').text, b.cert_pem)
        self.assertEqual(cmds[2].find('DATA').text.strip(), b.chain_pems[0].strip())
        self.assertEqual(self.make(ctx).served_wait({}), (40, 15))

    def test_no_ca_redfish_reset(self):
        ctx = FakeCtx(self.routes())
        self.make(ctx).deploy(rsa(), {'send_ca': False, 'reset': 'redfish'})
        self.assertEqual(len(ET.fromstring(ctx.calls[0]['body']).findall('CMD')), 2)
        self.assertEqual(json.loads(ctx.find('POST', 'Manager.Reset')[0]['body']),
                         {'ResetType': 'GracefulRestart'})
        self.assertFalse(ctx.find('POST', 'Oem/iRMC/Reset'))

    def test_no_reset_warned(self):
        ctx = FakeCtx(self.routes())
        t = self.make(ctx)
        t.deploy(rsa(), {'reset': 'none'})
        self.assertEqual(len(ctx.calls), 1)
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'next reset' in w])
        self.assertIsNone(t.served_wait({'reset': 'none'}))

    def test_refused_said_and_no_reset(self):
        bad = (200, '<?xml version="1.0"?><CMDSEQ><CMD Context="SCCI" OC="E002" OE="1981">'
                    '<STATUS>15</STATUS><MESSAGE>invalid key</MESSAGE></CMD></CMDSEQ>')
        ctx = FakeCtx(self.routes(scci=bad))
        with self.assertRaises(PluginError) as e:
            self.make(ctx).deploy(rsa(), {})
        self.assertIn('status 15 - invalid key', str(e.exception))
        self.assertIn('M8', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse(ctx.find('POST', 'Reset'), 'no reset after a refusal')

    def test_ec_key_refused_before_anything(self):
        ctx = FakeCtx(self.routes())
        with self.assertRaises(PluginError) as e:
            self.make(ctx).deploy(FakeBundle(), {})
        self.assertIn('RSA', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_try_reads_only(self):
        ctx = FakeCtx(self.routes())
        words = self.make(ctx).test()
        self.assertIn('SCCI answered', words)
        self.assertEqual(len(ctx.calls), 1)
        cmd = ET.fromstring(ctx.calls[0]['body']).find('CMD')
        self.assertEqual((cmd.get('OC'), cmd.get('OE'), cmd.get('Type')), ('E001', '1982', 'GET'))

    def test_bad_password(self):
        ctx = FakeCtx([('POST', r'/config$', (401, b'Unauthorized'))])
        with self.assertRaises(PluginError) as e:
            self.make(ctx).test()
        self.assertIn('401', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_served_already(self):
        ctx = FakeCtx(self.routes())
        t = make('irmc', {'host': 'irmc.test', 'user': 'u', 'password': 'p'}, ctx)
        t.served_now = lambda b: True
        self.assertTrue(t.deploy(rsa(), {}).startswith('unchanged'))
        self.assertEqual(ctx.calls, [])
        self.assertEqual(t.served_places({}), [('irmc.test', 443)])

    def test_status_value_error_refused(self):
        # 1.0.96: an error in the shape of the OK answer (<Status><Value>N</Value>) was taken
        # as done - the iRMC reset with the old certificate
        bad = (200, '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><Status>'
                    '<Value>32</Value><Severity>Error</Severity>'
                    '<Message>Certificate does not match the key</Message></Status>')
        ctx = FakeCtx(self.routes(scci=bad))
        with self.assertRaises(PluginError) as e:
            self.make(ctx).deploy(rsa(), {})
        self.assertIn('status 32 - Certificate does not match the key', str(e.exception))
        self.assertFalse(ctx.find('POST', 'Reset'), 'no reset after a refusal')
        from acmelib.plugins.targets import irmc
        errors, _ = irmc.scci_result('<CMDSEQ><CMD OE="1981"><Status><Value>5</Value>'
                                     '<Message>bad key</Message></Status></CMD></CMDSEQ>')
        self.assertEqual(errors, ['SCCI 1981: status 5 - bad key'])
        self.assertEqual(irmc.scci_result(SCCI_OK), ([], {}))

    def test_served_now_ipv6(self):
        # 1.0.96: an IPv6 host asked as itself, not as "2001:db8::1:443"
        self.assertEqual(T.served_asked('irmc', {'user': 'u', 'password': 'p'}),
                         [('2001:db8::1', 8443)] * 2)


# ---------------------------------------------------------------------------
def redfish_root(extra=()):
    return list(extra) + [
        ('GET', r'/redfish/v1/$', (200, {'Links': {'Sessions': {
            '@odata.id': '/redfish/v1/SessionService/Sessions'}}})),
        ('POST', r'/SessionService/Sessions$', (201, {}, {
            'X-Auth-Token': 'TOK', 'Location': '/redfish/v1/SessionService/Sessions/3'})),
        ('DELETE', r'/Sessions/3$', (204, b'')),
        ('GET', r'/redfish/v1/Managers$', (200, {'Members': [{'@odata.id': '/redfish/v1/Managers/1'}]})),
        ('GET', r'/redfish/v1/Managers/1$', (200, {'Model': 'X13DEI', 'FirmwareVersion': '01.04.11'})),
    ]


class SupermicroTest(unittest.TestCase):
    def routes(self, upload=(200, {})):
        return redfish_root([
            ('GET', r'/UpdateService/Oem/Supermicro/SSLCert$', (200, {'VaildFrom': 'x'})),
            ('POST', r'/SSLCert/Actions/SmcSSLCert\.Upload$', upload),
            ('POST', r'/Managers/1/Actions/Manager\.Reset$', (204, b'')),
        ])

    def t(self, ctx, **cfg):
        return not_served(make('supermicro_bmc', dict({'host': 'bmc.test', 'user': 'svc-cert',
                                                        'password': 'pw'}, **cfg), ctx))

    def test_upload(self):
        ctx = FakeCtx(self.routes())
        b = FakeBundle()
        self.assertEqual(self.t(ctx).deploy(b, {}), 'uploaded the HTTPS certificate')
        up = ctx.find('POST', 'SmcSSLCert.Upload')[0]
        self.assertEqual(up['path'], '/redfish/v1/UpdateService/Oem/Supermicro/SSLCert/Actions/'
                                     'SmcSSLCert.Upload')
        self.assertEqual(up['headers']['X-Auth-Token'], 'TOK')
        parts = multipart_parts(up)
        self.assertEqual(sorted(parts), ['cert_file', 'key_file'])
        self.assertEqual(parts['cert_file'][1].decode(), b.fullchain_pem)
        self.assertEqual(parts['key_file'][1].decode(), b.key_pem)
        self.assertFalse(ctx.find('POST', 'Manager.Reset'))
        self.assertEqual(len(ctx.find('DELETE', 'Sessions/3')), 1, 'signed out')

    def test_leaf_only_reset_basic(self):
        ctx = FakeCtx(self.routes())
        b = FakeBundle()
        t = self.t(ctx, basic_auth=True)
        self.assertIn('BMC resets', t.deploy(b, {'with_chain': False, 'reset': True}))
        self.assertEqual(multipart_parts(ctx.find('POST', 'Upload')[0])['cert_file'][1].decode(),
                         b.cert_pem)
        self.assertEqual(json.loads(ctx.find('POST', 'Manager.Reset')[0]['body']),
                         {'ResetType': 'GracefulRestart'})
        self.assertFalse(ctx.find('POST', 'Sessions$'))
        self.assertEqual(t.served_wait({'reset': True}), (20, 15))

    def test_no_oem_action(self):
        ctx = FakeCtx(self.routes(upload=(404, {'error': {'message': 'not found'}})))
        with self.assertRaises(PluginError) as e:
            self.t(ctx).deploy(FakeBundle(), {})
        self.assertIn('no SmcSSLCert.Upload', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_try(self):
        ctx = FakeCtx(self.routes())
        self.assertIn('X13DEI', self.t(ctx).test())
        self.assertEqual({c['method'] for c in ctx.calls}, {'GET', 'POST', 'DELETE'})
        self.assertFalse(ctx.find('POST', 'Upload|Reset'))


# ---------------------------------------------------------------------------
def nuova(call):
    b = call['body'].decode()
    if b.startswith('<aaaLogin'):
        if "inPassword=\"bad\"" in b:
            return (200, '<aaaLogin cookie="" response="yes" errorCode="551" '
                         'invocationResult="unidentified-fail" errorDescr="Authentication failed"/>')
        return (200, '<aaaLogin cookie="" response="yes" outCookie="1700000000/abcd" '
                     'outRefreshPeriod="600" outPriv="admin"/>')
    if b.startswith('<aaaLogout'):
        return (200, '<aaaLogout cookie="" response="yes" outStatus="success"/>')
    if b.startswith('<configResolveDn'):
        return (200, '<configResolveDn dn="sys/cert-mgmt/curr-cert" response="yes"><outConfig>'
                     '<currentCertificate dn="sys/cert-mgmt/curr-cert" commonName="cimc.test" '
                     'validTo="Jan 30 2027"/></outConfig></configResolveDn>')
    return (200, '<configConfMo dn="x" cookie="" response="yes"><outConfig/></configConfMo>')


class CiscoImcTest(unittest.TestCase):
    def t(self, ctx, pw='pw'):
        return not_served(make('cisco_imc', {'host': 'cimc.test', 'user': 'svc-cert',
                                              'password': pw}, ctx))

    def bodies(self, ctx):
        return [c['body'].decode() for c in ctx.calls]

    def test_external_certificate(self):
        ctx = FakeCtx([('POST', r'/nuova$', nuova)])
        b = rsa()
        self.assertIn('activated', self.t(ctx).deploy(b, {}))
        bodies = self.bodies(ctx)
        self.assertEqual(len(bodies), 4, 'login, cert, key, activate (the session gone after)')
        self.assertTrue(all(c['path'] == '/nuova' for c in ctx.calls))
        login = ET.fromstring(bodies[0])
        self.assertEqual((login.tag, login.get('inName'), login.get('inPassword')),
                         ('aaaLogin', 'svc-cert', 'pw'))
        cert = ET.fromstring(bodies[1])
        self.assertEqual((cert.tag, cert.get('dn'), cert.get('cookie')),
                         ('configConfMo', 'sys/cert-mgmt/external-cert-upload', '1700000000/abcd'))
        up = cert.find('inConfig/uploadExternalCertificate')
        self.assertEqual(up.get('adminAction'), 'content-cert-upload')
        self.assertEqual(up.get('certificateContent'), b.cert_pem, 'line ends kept (&#10;)')
        key = ET.fromstring(bodies[2]).find('inConfig/uploadExternalPrivateKey')
        self.assertEqual(key.get('dn'), 'sys/cert-mgmt/external-pvt-key-upload')
        self.assertIn('BEGIN RSA PRIVATE KEY', key.get('certificateContent'))
        act = ET.fromstring(bodies[3])
        self.assertEqual(act.get('dn'), 'sys/cert-mgmt')
        self.assertEqual(act.find('inConfig/certificateManagement').get('adminAction'),
                         'activate-external-cert')

    def test_chain_and_error(self):
        def refuse(call):
            if 'uploadExternalPrivateKey' in call['body'].decode():
                return (200, '<configConfMo dn="sys/cert-mgmt/external-pvt-key-upload" '
                             'response="yes" errorCode="103" errorDescr="Key does not match"/>')
            return nuova(call)
        ctx = FakeCtx([('POST', r'/nuova$', refuse)])
        b = rsa()
        with self.assertRaises(PluginError) as e:
            self.t(ctx).deploy(b, {'with_chain': True})
        self.assertIn('error 103 - Key does not match', str(e.exception))
        bodies = self.bodies(ctx)
        self.assertEqual(ET.fromstring(bodies[1]).find('inConfig/uploadExternalCertificate')
                         .get('certificateContent'), b.fullchain_pem)
        self.assertFalse([x for x in bodies if 'activate-external-cert' in x], 'not activated')
        self.assertTrue(bodies[-1].startswith('<aaaLogout'), 'signed out')

    def test_bad_login_and_ec(self):
        ctx = FakeCtx([('POST', r'/nuova$', nuova)])
        with self.assertRaises(PluginError) as e:
            self.t(ctx, pw='bad').test()
        self.assertIn('551', str(e.exception))
        self.assertFalse(e.exception.retry)
        ctx = FakeCtx([('POST', r'/nuova$', nuova)])
        with self.assertRaises(PluginError):
            self.t(ctx).deploy(FakeBundle(), {})
        self.assertEqual(ctx.calls, [])

    def test_try(self):
        ctx = FakeCtx([('POST', r'/nuova$', nuova)])
        self.assertIn('cimc.test, valid to Jan 30 2027', self.t(ctx).test())
        self.assertFalse([b for b in self.bodies(ctx) if 'configConfMo' in b])


# ---------------------------------------------------------------------------
class HuaweiTest(unittest.TestCase):
    def routes(self, imp=(200, {'@Message.ExtendedInfo': [{'MessageId': 'iBMC.1.0.CertImportOK'}]})):
        return redfish_root([
            ('POST', r'/UpdateService/FirmwareInventory$', (202, {'Id': '1'})),
            ('POST', r'/HttpsCert/Actions/HttpsCert\.ImportCustomCertificate$', imp),
            ('POST', r'/Managers/1/Actions/Manager\.Reset$', (200, {})),
            ('GET', r'/Managers/1/SecurityService/HttpsCert$', (200, {
                'X509CertificateInformation': {'Subject': 'CN=ibmc', 'ValidNotAfter': '2027'},
                'Actions': {'#HttpsCert.ImportCustomCertificate': {}}})),
        ])

    def t(self, ctx, **cfg):
        return not_served(make('huawei_ibmc', dict({'host': 'ibmc.test', 'user': 'svc-cert',
                                                     'password': 'pw'}, **cfg), ctx))

    def test_upload_import_restart(self):
        ctx = FakeCtx(self.routes())
        b = FakeBundle()
        self.assertIn('iBMC restarts', self.t(ctx).deploy(b, {}))
        up = ctx.find('POST', 'FirmwareInventory')[0]
        parts = multipart_parts(up)
        fn, pfx = parts['imgfile']
        self.assertTrue(re.match(r'^acme-[0-9a-f]+\.pfx$', fn), fn)
        imp = ctx.find('POST', 'ImportCustomCertificate')[0]
        self.assertEqual(imp['path'], '/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/'
                                      'HttpsCert.ImportCustomCertificate')
        body = json.loads(imp['body'])
        self.assertEqual((body['Type'], body['Content']), ('URI', '/tmp/web/' + fn))
        # the PKCS#12 opens with the password sent, and holds this certificate
        out = subprocess.run(['openssl', 'pkcs12', '-nokeys', '-passin', 'pass:' + body['Password']],
                             input=pfx, capture_output=True)
        if out.returncode != 0:     # OpenSSL 3 and a legacy PKCS#12
            out = subprocess.run(['openssl', 'pkcs12', '-legacy', '-nokeys', '-passin',
                                  'pass:' + body['Password']], input=pfx, capture_output=True)
        self.assertIn(b'BEGIN CERTIFICATE', out.stdout)
        self.assertEqual(json.loads(ctx.find('POST', 'Manager.Reset')[0]['body']),
                         {'ResetType': 'ForceRestart'})
        self.assertTrue(all(c['headers'].get('X-Auth-Token') == 'TOK' for c in ctx.calls
                            if c['method'] == 'POST' and 'Sessions' not in c['path']))
        self.assertTrue([w for lvl, w in ctx.steps if 'CertImportOK' in w])
        self.assertNotIn(body['Password'], json.dumps(ctx.steps))

    def test_blade_no_restart_and_refusal(self):
        ctx = FakeCtx(self.routes() + [
            ('POST', r'/Managers/Blade2/SecurityService/.*Import', (200, {})),
            ('GET', r'/Managers/Blade2/SecurityService/HttpsCert$', (200, {}))])
        t = self.t(ctx, manager='Blade2')
        t.deploy(FakeBundle(), {'reset': False})
        self.assertEqual(ctx.find('POST', 'Import')[0]['path'].split('/')[4], 'Blade2')
        self.assertFalse(ctx.find('POST', 'Manager.Reset'))
        self.assertIsNone(t.served_wait({'reset': False}))
        ctx = FakeCtx(self.routes(imp=(400, {'error': {'message': 'CertImportFailed'}})))
        with self.assertRaises(PluginError) as e:
            self.t(ctx).deploy(FakeBundle(), {})
        self.assertIn('400', str(e.exception))
        self.assertFalse(ctx.find('POST', 'Manager.Reset'))
        with self.assertRaises(PluginError):
            self.t(FakeCtx(self.routes()), manager='../x').deploy(FakeBundle(), {})

    def test_try(self):
        ctx = FakeCtx(self.routes())
        self.assertIn('CN=ibmc, valid to 2027', self.t(ctx).test())
        self.assertFalse(ctx.find('POST', 'Import|Firmware|Reset'))


# ---------------------------------------------------------------------------
class IsmTest(unittest.TestCase):
    def setUp(self):
        FakeFtp.reset()

    def t(self, ssh, **cfg):
        ctx = FakeCtx(ssh=ssh)
        t = with_ftp(not_served(make('fujitsu_ism', dict({'host': 'ism.test',
                                                          'user': 'administrator',
                                                          'password': 'pw'}, **cfg), ctx)))
        return t, ctx

    def test_ftp_set_restart(self):
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        b = FakeBundle()
        self.assertIn('ISM-VA restarts', t.deploy(b, {}))
        base = 'acme-%s' % C.short_serial(b)
        stors = [x[1] for x in FakeFtp.log if x[0] == 'stor']
        self.assertEqual(stors, ['Administrator/ftp/%s.key' % base,
                                 'Administrator/ftp/%s.crt' % base])
        self.assertIn(('new', 'plain'), FakeFtp.log, 'the ISM-VA has no FTPS')
        self.assertIn(('login', 'administrator', 'pw'), FakeFtp.log)
        self.assertEqual([c for c, _ in ssh.runs],
                         ['ismadm sslcert set -key /Administrator/ftp/%s.key '
                          '-crt /Administrator/ftp/%s.crt' % (base, base),
                          'ismadm power restart'])
        self.assertEqual(ssh.conns[0]['port'], 22)
        self.assertEqual(ssh.conns[0]['password'], 'pw')
        # deleted before the restart, nothing left there
        self.assertEqual(FakeFtp.files, {})
        dele = [i for i, x in enumerate(FakeFtp.log) if x[0] == 'dele']
        self.assertEqual(len(dele), 2)
        self.assertEqual(t.served_places({}), [('ism.test', 25566)])
        self.assertEqual(t.served_wait({}), (40, 15))

    def test_chain_and_no_restart(self):
        ssh = FakeSsh()
        t, ctx = self.t(ssh, group='Ops')
        b = FakeBundle()
        captured = {}
        orig = FakeFtp.storbinary

        def keep(self_, cmd, fh):
            data = fh.read()
            captured[cmd.split(' ', 1)[1]] = data
            FakeFtp.files[cmd.split(' ', 1)[1]] = data
        FakeFtp.storbinary = keep
        try:
            t.deploy(b, {'restart': False, 'with_chain': False})
        finally:
            FakeFtp.storbinary = orig
        crt = [v for k, v in captured.items() if k.endswith('.crt')][0]
        self.assertEqual(crt.decode(), b.cert_pem)
        self.assertTrue(all(k.startswith('Ops/ftp/') for k in captured))
        self.assertEqual(len(ssh.runs), 1)
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn'])

    def test_set_refused_files_deleted_no_restart(self):
        ssh = FakeSsh([(r'sslcert set', (1, '', 'Error: the certificate does not match the key'))])
        t, ctx = self.t(ssh)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('does not match', str(e.exception))
        self.assertEqual(FakeFtp.files, {}, 'the key deleted after a failure too')
        self.assertEqual(len(ssh.runs), 1, 'no restart')

    def test_crt_refused_key_taken_away(self):
        # 1.0.96: the key stayed on the FTP server when the certificate upload failed
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        orig = refuse_crt()
        try:
            with self.assertRaises(PluginError) as e:
                t.deploy(FakeBundle(), {})
        finally:
            FakeFtp.storbinary = orig
        self.assertIn('552', str(e.exception))
        self.assertEqual(FakeFtp.files, {})
        self.assertTrue([x for x in FakeFtp.log if x[0] == 'dele' and x[1].endswith('.key')])
        self.assertEqual(ssh.runs, [])
        self.assertFalse([w for lvl, w in ctx.steps if lvl == 'warn'],
                         'no warning for the certificate that never got there')

    def test_session_expired_reconnects_for_delete(self):
        t, ctx = self.t(FakeSsh())
        orig = expire_once()
        try:
            t.deploy(FakeBundle(), {})
        finally:
            FakeFtp.delete = orig
        self.assertEqual(FakeFtp.files, {}, 'deleted over a new session')
        self.assertEqual(len([x for x in FakeFtp.log if x[0] == 'login']), 2)
        self.assertFalse([w for lvl, w in ctx.steps if lvl == 'warn'])

    def test_restart_cut_is_expected(self):
        # 1.0.96: the real SSH session raises when the restart cuts it - no failure, remembered
        for cut in ('ssh to ism.test: Connection to ism.test closed by remote host.',
                    'ssh on ism.test took more than 120 s'):
            FakeFtp.reset()

            def go(cmd, inp, cut=cut):
                raise PluginError(cut)
            ssh = FakeSsh([(r'power restart', go)])
            t, ctx = self.t(ssh)
            self.assertIn('ISM-VA restarts', t.deploy(FakeBundle(), {}))
            self.assertTrue(ctx.kv, 'the deployment remembered')
        ssh = FakeSsh([(r'power restart', (1, '', 'Error: permission denied'))])
        with self.assertRaises(PluginError) as e:
            self.t(ssh)[0].deploy(FakeBundle(), {})
        self.assertIn('permission denied', str(e.exception))

    def test_ftp_refused(self):
        FakeFtp.refuse_login = True
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('did not let administrator in', str(e.exception))
        self.assertEqual(ssh.runs, [])

    def test_try(self):
        ssh = FakeSsh([(r'sslcert show', (0, 'Issuer: CN=ISM CA\nSubject: CN=ism.test\n', ''))])
        t, ctx = self.t(ssh)
        self.assertIn('Issuer: CN=ISM CA', t.test())
        self.assertEqual([c for c, _ in ssh.runs], ['ismadm sslcert show'])
        self.assertFalse([x for x in FakeFtp.log if x[0] in ('stor', 'dele')])
        with self.assertRaises(PluginError):
            self.t(FakeSsh(), group='a b')[0].test()


# ---------------------------------------------------------------------------
class EternusTest(unittest.TestCase):
    CFG = {'host': 'dx.test', 'user': 'svc-cert', 'auth': 'password', 'password': 'pw',
           'ftp_host': 'ftp.test', 'ftp_user': 'stage', 'ftp_password': 'ftppw'}

    def setUp(self):
        FakeFtp.reset()

    def t(self, ssh, **cfg):
        ctx = FakeCtx(ssh=ssh)
        return with_ftp(not_served(make('eternus_dx', dict(self.CFG, **cfg), ctx))), ctx

    def test_ftps_import(self):
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        b = rsa()
        self.assertEqual(t.deploy(b, {}), 'registered the SSL certificate')
        base = 'acme-%s' % C.short_serial(b)
        self.assertIn(('new', 'tls'), FakeFtp.log)
        self.assertIn(('prot_p',), FakeFtp.log)
        self.assertEqual([x[1] for x in FakeFtp.log if x[0] == 'stor'],
                         [base + '.key', base + '.crt'])
        self.assertEqual(ssh.runs, [(
            'import ssl-certificate -port maintenance -server ftp.test -user stage '
            '-cert-filename %s.crt -key-filename %s.key' % (base, base), 'ftppw\n')])
        self.assertEqual(FakeFtp.files, {}, 'the key does not stay on the file server')
        self.assertNotIn('ftppw', json.dumps(ctx.steps))
        self.assertEqual(t.served_places({}), [('dx.test', 443)])

    def test_plain_ftp_port_folder_smis(self):
        ssh = FakeSsh()
        t, ctx = self.t(ssh, ftp_mode='ftp', ftp_port=2121, ftp_folder='/eternus/',
                        lan_port='remote')
        b = rsa()
        stored = {}
        orig = FakeFtp.storbinary

        def keep(self_, cmd, fh):
            stored[cmd.split(' ', 1)[1]] = fh.read()
        FakeFtp.storbinary = keep
        try:
            self.assertIn('SMI-S restarted', t.deploy(b, {'smis': True, 'with_chain': True}))
        finally:
            FakeFtp.storbinary = orig
        base = 'acme-%s' % C.short_serial(b)
        self.assertEqual(stored['eternus/%s.crt' % base].decode(), b.fullchain_pem)
        self.assertIn(b'BEGIN RSA PRIVATE KEY', stored['eternus/%s.key' % base])
        self.assertEqual([c for c, _ in ssh.runs], [
            'import ssl-certificate -port remote -server ftp.test -user stage -cert-filename '
            'eternus/%s.crt -key-filename eternus/%s.key -server-port-number 2121 '
            '-disable-ftps yes' % (base, base),
            'set smi-s -function disable',
            'set smi-s -function enable -ssl-certificate shared-with-webgui'])
        self.assertIn(('new', 'plain'), FakeFtp.log)

    def test_old_generation_plain_ftp_no_option(self):
        ssh = FakeSsh()
        t, ctx = self.t(ssh, ftp_mode='ftp_old')
        t.deploy(rsa(), {})
        self.assertIn(('new', 'plain'), FakeFtp.log)
        self.assertNotIn('ftps', ssh.runs[0][0])

    def test_cli_error_and_ec(self):
        ssh = FakeSsh([(r'import ssl', (0, 'Error: E0019 Inconsistent parameter\n', ''))])
        t, ctx = self.t(ssh)
        with self.assertRaises(PluginError) as e:
            t.deploy(rsa(), {})
        self.assertIn('E0019', str(e.exception))
        self.assertEqual(FakeFtp.files, {})
        FakeFtp.reset()
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {})
        self.assertEqual((ssh.runs, FakeFtp.log), ([], []))
        with self.assertRaises(PluginError) as e:
            self.t(FakeSsh(), ftp_user='a b')[0].deploy(rsa(), {})
        self.assertIn('user', str(e.exception))

    def test_crt_refused_key_taken_away(self):
        # 1.0.96: the key stayed on the file server when the certificate upload failed
        ssh = FakeSsh()
        t, ctx = self.t(ssh)
        orig = refuse_crt()
        try:
            with self.assertRaises(PluginError):
                t.deploy(rsa(), {})
        finally:
            FakeFtp.storbinary = orig
        self.assertEqual(FakeFtp.files, {})
        self.assertEqual(ssh.runs, [])

    def test_session_expired_reconnects_for_delete(self):
        t, ctx = self.t(FakeSsh())
        orig = expire_once()
        try:
            t.deploy(rsa(), {})
        finally:
            FakeFtp.delete = orig
        self.assertEqual(FakeFtp.files, {})
        self.assertEqual(len([x for x in FakeFtp.log if x[0] == 'prot_p']), 2,
                         'the new session is FTPS again')

    def test_try(self):
        ssh = FakeSsh([(r'show ssl-version', (0, 'Protocol  TLS1.2  TLS1.3\nMNT  Enable\n', ''))])
        t, ctx = self.t(ssh)
        self.assertIn('TLS1.2', t.test())
        self.assertEqual([c for c, _ in ssh.runs], ['show ssl-version'])
        self.assertFalse([x for x in FakeFtp.log if x[0] in ('stor', 'dele')])


if __name__ == '__main__':
    unittest.main(verbosity=1)
