# -*- coding: utf-8 -*-
"""
Cisco Secure Firewall Management Center - versions of the cisco_fmc target (1.0.95).

The plain cisco_fmc (cisco_fmc.py, unchanged) imports the certificate as an Internal
Certificate and switches decryption rules to it - the same calls in FMC 7.4 - 10.0. From FMC
7.7 the REST API also enrols a certificate on the devices (Devices → Certificates: the
trustpoint of RA VPN, SAML...), which 7.4 / 7.6 cannot do over the API
(devices/operational/managecertificates and devices/certificates are 7.7 and later):

  '7.7'     FMC 7.7 - 10.0   besides what the plain one does: a PKCS12 Cert Enrollment
                             object of a fixed name (made, or its PKCS#12 replaced), enrolled
                             on the devices asked (ENROLL, or RE_ENROLL where it is already),
                             so the trustpoint the RA VPN names keeps its name

    GET  /api/fmc_platform/v1/info/serverversion          -> items[0].serverVersion
    GET  /api/fmc_config/v1/domain/<d>/object/certenrollments?offset=&limit=
    POST /api/fmc_config/v1/domain/<d>/object/certenrollments
    PUT  /api/fmc_config/v1/domain/<d>/object/certenrollments/<id>
         {"type": "CertEnrollment", "name", "enrollmentType": "PKCS12",
          "pkcs12Content": {"base64Certificate", "passPhrase"},
          "validationUsage": {"ipsecClient": true, "sslServer": true}}
    GET  /api/fmc_config/v1/domain/<d>/devices/devicerecords?offset=&limit=
    GET  /api/fmc_config/v1/domain/<d>/devices/certificates?filter=deviceId:<id>&expanded=true
    POST /api/fmc_config/v1/domain/<d>/devices/operational/managecertificates
         {"action": "ENROLL" | "RE_ENROLL", "deviceCertificates": [{"deviceId",
          "certificates": [{"certificate": {"id": <enrollment>}}]}]}

The versioned class refuses an FMC that says another version before anything is changed.

Sources (the vendor guide navody/certifikaty/cisco/fmc-ftd.md and what it cites):
    https://www.cisco.com/c/en/us/td/docs/security/firepower/10-0/API/REST/firepower_management_center_rest_api_quick_start_guide_10_0/Objects_In_The_REST_API.html
    https://www.cisco.com/c/en/us/td/docs/security/firepower/10-0/API/REST/firepower_management_center_rest_api_quick_start_guide_10_0/About_The_Firepower_Management_Center_REST_API.html
    https://github.com/CiscoDevNet/terraform-provider-fmc (fmc_certificate_enrollment,
      fmc_device_certificate)

Less certain (the guide marks them): the fields of certenrollments are from Cisco's Terraform
provider, not the API reference; whether PUT of an enrolled PKCS12 object followed by
RE_ENROLL puts the new PKCS#12 on the device (acme reads devices/certificates afterwards and
says what it finds); managecertificates runs as a task - acme does not wait for it; the
serverversion call is FMC's usual one, not quoted by the guide.
"""
from __future__ import annotations

import base64
import re

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, text, random_password)
from acmelib.plugins.targets.cisco_fmc import CiscoFmcTarget, q
from acmelib.plugins.targets._cisco_aruba import Ranges, VersionCheck

RANGES = Ranges((('7.7', 'FMC 7.7 - 10.0', (7, 7, 0), None),),
                plain_label='(the plain one, no version)')


def parse_fmc(v):
    m = re.match(r'^\s*(\d+)\.(\d+)(?:\.(\d+))?', text(v))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


class CiscoFmc77Target(VersionCheck, CiscoFmcTarget):
    """FMC 7.7 - 10.0: the device certificates (trustpoints) through managecertificates."""
    module_version, version_label, sw_min, sw_max = RANGES.ranges[0]
    ranges = RANGES
    sw_name = 'FMC'
    sw_checked_to = (10, 0)
    description = ('FMC 7.7 - 10.0: besides the Internal Certificate for decryption rules (as '
                   'the plain version), puts the certificate into a PKCS12 Cert Enrollment '
                   'object of a fixed name and enrols it on the devices asked (Devices → '
                   'Certificates), so the trustpoint RA VPN uses keeps its name and gets the '
                   'new certificate. Refused on an FMC that says another version.')
    deploy_fields = CiscoFmcTarget.deploy_fields[:-1 - 2] + [
        field('enrollment', 'Cert Enrollment object (PKCS12)', 'text',
              placeholder='RAVPN-acme',
              help='the name of the PKCS12 enrollment object - the trustpoint on the devices; '
                   'made the first time, its PKCS#12 replaced at each renewal; empty: no '
                   'device certificate'),
        field('enroll_devices', 'Enrol on these devices', 'list', placeholder='ftd-1',
              help='one a line: device names as the FMC lists them'),
        field('internal', 'Also an Internal Certificate', 'bool', default=True,
              help='the Internal Certificate for decryption rules, as the plain version (off: '
                   'only the device certificate)'),
    ] + CiscoFmcTarget.deploy_fields[-1 - 2:]

    def sw_version(self):
        if '_ver' not in self.__dict__:
            self._ver = None
            try:
                self.login()
                st, hd, d = self.req('GET', '/api/fmc_platform/v1/info/serverversion',
                                     what='reading the FMC version')
                items = d.get('items') if isinstance(d, dict) else None
                self._ver = parse_fmc((items or [{}])[0].get('serverVersion'))
            except PluginError as e:
                self.ctx.debug('the FMC version cannot be read: %s' % e)
        return self._ver

    def test(self):
        words = CiscoFmcTarget.test(self)
        self.check_version()
        ver = self.sw_version()
        return words + ('; FMC %s' % '.'.join(map(str, ver)) if ver else '')

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the FMC')
        self.check_version()
        did = []
        enr = text(options.get('enrollment')).strip()
        if enr:
            did.append(self.enrol(bundle, options, enr))
        if as_bool(self.opt(options, 'internal', True), True) or not enr:
            did.append(CiscoFmcTarget.deploy(self, bundle, options))
        else:
            self.remember(bundle, options)
        return ', '.join(x for x in did if x)

    # -- the device certificate -------------------------------------------------------------
    def enrol(self, bundle, options, enr):
        pw = random_password(20)
        p12 = bundle.as_format('pfx', password=pw, alias=enr)
        body = {'type': 'CertEnrollment', 'name': enr, 'enrollmentType': 'PKCS12',
                'pkcs12Content': {'base64Certificate': base64.b64encode(p12).decode(),
                                  'passPhrase': pw},
                'validationUsage': {'ipsecClient': True, 'sslServer': True}}
        # the devices listed and checked before the object is made or replaced (1.0.96): a
        # device name the FMC does not know left a changed Cert Enrollment, enrolled nowhere
        want = lines(options.get('enroll_devices'))
        devs = {}
        if want:
            devs = {text(d.get('name')): text(d.get('id')) for d in
                    self.paged('/devices/devicerecords', 'listing the devices')}
            missing = [n for n in want if n not in devs]
            if missing:
                raise PluginError('the FMC has no device %s' % ', '.join(missing), retry=False)
        objs = self.paged('/object/certenrollments', 'listing the Cert Enrollment objects')
        obj = next((o for o in objs if text(o.get('name')) == enr), None)
        if obj is None:
            st, obj = self.api('POST', '/object/certenrollments', body,
                               what='making the Cert Enrollment %s' % enr)
            self.ctx.step('made the PKCS12 Cert Enrollment %s' % enr, 'ok')
        else:
            if text(obj.get('enrollmentType')).upper() not in ('', 'PKCS12'):
                raise PluginError('the Cert Enrollment %s is of the type %s - acme puts a '
                                  'PKCS#12 only into a PKCS12 one' % (enr,
                                                                     obj.get('enrollmentType')),
                                  retry=False)
            body['id'] = text(obj.get('id'))
            st, got = self.api('PUT', '/object/certenrollments/%s' % q(obj.get('id')), body,
                               what='replacing the PKCS#12 of %s' % enr)
            obj = got or obj
            self.ctx.step('replaced the PKCS#12 of the Cert Enrollment %s' % enr, 'ok')
        eid = text(obj.get('id'))
        if not eid:
            raise PluginError('the FMC gave no id for %s' % enr, retry=False)
        if not want:
            self.ctx.step('no device to enrol %s on - give the devices' % enr, 'warn')
            return 'Cert Enrollment %s' % enr
        done = []
        for n in want:
            st, d = self.api('GET', '/devices/certificates?filter=%s&expanded=true'
                             % q('deviceId:%s' % devs[n]),
                             what='reading the certificates of %s' % n)
            has = any(eid in str(x) for x in (d.get('items') or []))
            action = 'RE_ENROLL' if has else 'ENROLL'
            self.api('POST', '/devices/operational/managecertificates', {
                'action': action, 'deviceCertificates': [{
                    'deviceId': devs[n], 'certificates': [{'certificate': {'id': eid}}]}]},
                what='%s %s on %s' % (action.lower().replace('_', '-'), enr, n))
            self.ctx.step('%s of %s asked on %s' % (action, enr, n), 'ok')
            done.append(n)
        return 'enrolled %s on %s' % (enr, ', '.join(done))
