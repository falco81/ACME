# -*- coding: utf-8 -*-
"""
Cisco Catalyst 9800 Wireless LAN Controllers (IOS XE) over SSH: as cisco_iosxe - the PKCS#12
copied to bootflash: with SCP, imported into a new trustpoint, the web admin (HTTPS server:
GUI, RESTCONF) pointed at it and restarted - and, when asked, the web authentication (guest
portal) of a webauth parameter map:

    shell  configure terminal
             parameter-map type webauth <global>
              trustpoint <tp>
             exit
             no ip http server
             ip http server
           end

The AP join certificates (MIC/SSC/LSC, `wireless management trustpoint`) are not touched:
changing them makes every AP join again - not a job for a renewal.

Versions (1.0.95), as cisco_iosxe (TN 213917, CSCvz41428: PKCS#12 with a SHA-256 MAC only
from 17.12.1):

  ''        any version - reads `show version`
  '17.3'    IOS XE 17.3 - 17.11      PKCS#12 3DES, SHA-1 MAC
  '17.12'   IOS XE 17.12 - 26.1      PKCS#12 AES-256

Sources (the vendor guide navody/certifikaty/cisco/wlc-9800.md and what it cites):
    https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/213917-generate-csr-for-third-party-certificate.html
    https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/221047-understand-certificate-and-trustpoint-ty.html
    https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/26-1/configuration-guide/wl-26-1-cg/pki-management/configuration-tasks.html

Less certain (besides those of cisco_iosxe): up to 17.8 the web admin and webauth send only
the certificate and its issuer, not the whole chain (CSCwa23606); the guide says to name the
PKCS#12 like the trustpoint so the WLC makes the trustpoints of a chain of several CAs
(<tp>, <tp>-rrr1 ...) - acme does.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import field, as_bool, text, verify_fields, keep_field
from acmelib.plugins.targets.cisco_iosxe import CiscoIosXeTarget, RANGES

WLC_FIELDS = [
    field('web_admin', 'Web admin (GUI, RESTCONF)', 'bool', default=True,
          help='ip http secure-trustpoint, then the HTTPS server restarted (GUI sessions are '
               'cut for a moment; APs and clients are not)'),
    field('webauth', 'Web authentication (guest portal)', 'bool', default=False,
          help='the trustpoint of a webauth parameter map, then the HTTP server restarted '
               '(guest sign-ins under way are redirected again)'),
    field('webauth_map', 'Webauth parameter map', 'text', default='global', advanced=True,
          help='parameter-map type webauth <name>; its virtual IP and virtual-host must be '
               'set and match the certificate\'s name'),
    field('webauth_host', 'Webauth virtual host', 'text', advanced=True,
          placeholder='guest.example.com',
          help='the virtual-host name of the portal, for the test of what is served'),
    field('save', 'Save the configuration (write memory)', 'bool', default=True),
    keep_field(1),
] + verify_fields()


class Wlc9800Mixin(object):
    def binds(self, options, name):
        out = CiscoIosXeTarget.binds(self, options, name)
        if as_bool(self.opt(options, 'webauth', False)):
            pm = text(self.opt(options, 'webauth_map', 'global')).strip() or 'global'
            out.append(('the webauth parameter map %s' % pm, [
                'parameter-map type webauth %s' % pm, 'trustpoint %s' % name, 'exit',
                'no ip http server', 'ip http server']))
        return out

    def bound(self, s, options):
        used = CiscoIosXeTarget.bound(self, s, options)
        out = self.exec_(s, 'show running-config | section parameter-map type webauth',
                         what='reading the webauth parameter maps')
        used.update(re.findall(r'^\s*trustpoint (\S+)', out, re.M))
        return used

    def served_places(self, options):
        got = CiscoIosXeTarget.served_places(self, options)
        host = text((options or {}).get('webauth_host')).strip()
        if host and as_bool((options or {}).get('webauth')):
            got.append((host, 443))
        return got


_DESC = ('Copies the certificate as PKCS#12 to the controller\'s bootflash: over SCP, imports '
         'it into a new trustpoint, uses it for the web admin (GUI, RESTCONF) and, when asked, '
         'the guest portal (webauth parameter map), restarts the HTTP(S) server, saves and '
         'removes the older acme trustpoints - over SSH.')


class CiscoWlc9800Target(Wlc9800Mixin, CiscoIosXeTarget):
    kind = 'cisco_wlc9800'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Cisco Catalyst 9800 Wireless Controller'
    description = _DESC + (' Any IOS XE 17.3 - 26.1: the PKCS#12 kind is taken from the '
                           'version the controller says.')
    deploy_fields = WLC_FIELDS


class CiscoWlc9800v173Target(Wlc9800Mixin, CiscoIosXeTarget):
    kind = 'cisco_wlc9800'
    discovery = False
    title = CiscoWlc9800Target.title
    module_version, version_label, sw_min, sw_max = RANGES.ranges[0]
    description = ('IOS XE 17.3 - 17.11: the PKCS#12 is made the old way (3DES, SHA-1 MAC) - '
                   'these versions refuse a SHA-256 MAC (CSCvz41428). ' + _DESC +
                   ' Refused on a controller that says another IOS XE.')
    deploy_fields = WLC_FIELDS
    p12_kind = 'p12-legacy'


class CiscoWlc9800v1712Target(Wlc9800Mixin, CiscoIosXeTarget):
    kind = 'cisco_wlc9800'
    discovery = False
    title = CiscoWlc9800Target.title
    module_version, version_label, sw_min, sw_max = RANGES.ranges[1]
    description = ('IOS XE 17.12 - 26.1 (17.12, 17.15, 17.18, 26.x): the PKCS#12 is AES-256 '
                   'with a SHA-256 MAC. ' + _DESC +
                   ' Refused on a controller that says another IOS XE.')
    deploy_fields = WLC_FIELDS
    p12_kind = 'pfx'
