# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# What an answer may carry, product by product (1.0.57)
# ---------------------------------------------------------------------------
# The catalogue the reply lines of a realm or a group are written from, and
# the pages' Ctrl+Space help is built from: the standard attributes and the
# vendor ones the common VPN concentrators, firewalls and gateways read.
# Names as in FreeRADIUS's dictionaries (v3). Vendor attributes are sent in a
# Vendor-Specific; any other one can still be written as
# Vendor-<vendor>-Attr-<number> = value (a string, or 0x... bytes).
REPLY_PRODUCTS = {
    'std': 'Standard (RFC)', 'asa': 'Cisco ASA / FTD (AnyConnect, Secure Client)',
    'ios': 'Cisco IOS / ISE / NX-OS', 'forti': 'Fortinet FortiGate', 'pan': 'Palo Alto Networks',
    'cp': 'Check Point', 'juniper': 'Juniper (Junos)', 'ivanti': 'Ivanti Connect Secure (Pulse)',
    'citrix': 'Citrix NetScaler / ADC Gateway', 'f5': 'F5 BIG-IP', 'sonic': 'SonicWall',
    'aruba': 'Aruba (HPE)', 'mikrotik': 'MikroTik', 'ms': 'Microsoft (RRAS)',
    'pfsense': 'pfSense', 'watchguard': 'WatchGuard Firebox', 'sophos': 'Sophos Firewall',
    'openvpn': 'OpenVPN Access Server', 'unifi': 'Ubiquiti UniFi', 'uag': 'Omnissa (VMware) Horizon UAG',
    'barracuda': 'Barracuda CloudGen', 'zyxel': 'Zyxel',
}
# What each product does with an answer, said once over its attributes.
REPLY_PRODUCT_SAYS = {
    'asa': 'Group policy: ASA-Group-Policy = name (preferred since 8.2; FTD takes name or OU=name). '
           'Older: Class = OU=name;. DAP rules can read ASA-Member-Of or Class.',
    'ios': 'Cisco-AVPair carries proto:attr=value pairs: shell:priv-lvl=15 for admins, '
           'ip:inacl#1=... per-user ACEs, ACS:CiscoSecure-Defined-ACL for an ISE dACL.',
    'forti': 'A user group whose RADIUS server has "match group-name X" is matched by '
             'Fortinet-Group-Name = X. Wildcard admins: Fortinet-Access-Profile and -Vdom-Name.',
    'pan': 'PaloAlto-User-Group = group, matched by the authentication profile\'s allow list '
           'or a GlobalProtect config. Admins: PaloAlto-Admin-Role.',
    'cp': 'Gaia admins: CP-Gaia-User-Role (and CP-Gaia-SuperUser-Access). Remote access VPN '
          'groups usually from Class.',
    'juniper': 'Junos logins: Juniper-Local-User-Name = a template user (its login class).',
    'ivanti': 'Role mapping can read any attribute: Class or Filter-Id = role name is usual. '
              'Framed-IP-Address for a fixed address.',
    'citrix': 'Group extraction reads a vendor attribute set on the radiusAction '
              '(groupVendorIdentifier 3845, groupAttributeType 1): Citrix-NS-User-Groups.',
    'f5': 'Admins: F5-LTM-User-Role (+ -Partition, -Shell). APM can branch on any attribute '
          '(session.radius.last.attr.class).',
    'sonic': 'SonicWall-User-Group = a SonicOS group (or Filter-Id, by the RADIUS settings).',
    'aruba': 'Aruba-User-Role = a role of the controller; or a VLAN.',
    'mikrotik': 'Mikrotik-Group for router logins, Mikrotik-Rate-Limit for speed, '
                'Framed-Pool for PPP.',
    'watchguard': 'The only group attribute read is Filter-Id = group.',
    'sophos': 'The group comes from the attribute set as "Group name attribute": Filter-Id or Class.',
    'openvpn': 'The group comes from Framed-Pool (the post-auth script).',
    'unifi': 'VLAN by the standard three: Tunnel-Type = VLAN, Tunnel-Medium-Type = IEEE-802, '
             'Tunnel-Private-Group-Id = the VLAN.',
    'uag': 'Only Accept or Reject is used - no attribute is read. A challenge shows '
           'Reply-Message as its prompt. Entitlements come from Active Directory.',
    'barracuda': 'The group is read from Class or Filter-Id (parsed by its delimiter).',
    'pfsense': 'Bandwidth by pfSense-Bandwidth-Max-Up/-Down; groups usually by Class.',
}
_R = []


def _ra(name, vendor, num, kind, says, ex, products, values=None):
    _R.append({'name': name, 'vendor': vendor, 'num': num, 'type': kind, 'says': says,
               'example': ex, 'products': products, 'values': values or {}})


# ---- standard ----
_ra('Reply-Message', 0, 18, 'string', 'Text shown to the person (a challenge\'s prompt).',
    'Welcome', ['std', 'uag', 'ivanti'])
_ra('Class', 0, 25, 'string', 'A tag the NAS keeps and echoes in accounting; the group or '
    'policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM.', 'OU=GP_FULL;',
    ['std', 'asa', 'sophos', 'ivanti', 'barracuda', 'pfsense', 'cp', 'f5'])
_ra('Filter-Id', 0, 11, 'string', 'Name of a filter/ACL or of a group (WatchGuard, SonicWall, '
    'Sophos, ASA ACL).', 'VPN-Admins', ['std', 'watchguard', 'sonic', 'sophos', 'asa', 'ivanti'])
_ra('Session-Timeout', 0, 27, 'integer', 'Longest session, in seconds.', '43200', ['std'])
_ra('Idle-Timeout', 0, 28, 'integer', 'Seconds without traffic before it ends.', '1800', ['std'])
_ra('Service-Type', 0, 6, 'integer', 'The kind of service; Administrative-User or NAS-Prompt-User '
    'for logins to the device itself.', 'Administrative-User', ['std', 'ios', 'asa'],
    {1: 'Login-User', 2: 'Framed-User', 3: 'Callback-Login-User', 4: 'Callback-Framed-User',
     5: 'Outbound-User', 6: 'Administrative-User', 7: 'NAS-Prompt-User',
     8: 'Authenticate-Only', 9: 'Callback-NAS-Prompt', 10: 'Call-Check',
     11: 'Callback-Administrative'})
_ra('Framed-Protocol', 0, 7, 'integer', 'Framing of a PPP/L2TP session.', 'PPP', ['std'],
    {1: 'PPP', 2: 'SLIP', 3: 'ARAP', 4: 'Gandalf-SLML', 5: 'Xylogics-IPX-SLIP',
     6: 'X.75-Synchronous'})
_ra('Framed-IP-Address', 0, 8, 'ipaddr', 'A fixed address for this person\'s tunnel.',
    '10.10.20.15', ['std', 'asa', 'ivanti', 'mikrotik', 'forti'])
_ra('Framed-IP-Netmask', 0, 9, 'ipaddr', 'Its netmask.', '255.255.255.0', ['std', 'asa'])
_ra('Framed-Route', 0, 22, 'string', 'A route pushed for this person.', '192.168.50.0/24 0.0.0.0 1',
    ['std'])
_ra('Framed-MTU', 0, 12, 'integer', 'MTU of the tunnel.', '1400', ['std'])
_ra('Framed-Pool', 0, 88, 'string', 'Name of an address pool; the group for OpenVPN Access '
    'Server.', 'vpn-pool-staff', ['std', 'openvpn', 'mikrotik'])
_ra('Acct-Interim-Interval', 0, 85, 'integer', 'Seconds between interim accounting updates.',
    '600', ['std'])
_ra('Termination-Action', 0, 29, 'integer', 'Ask again when the session times out (802.1X).',
    'RADIUS-Request', ['std'], {0: 'Default', 1: 'RADIUS-Request'})
_ra('Port-Limit', 0, 62, 'integer', 'Most ports/links at once.', '1', ['std'])
_ra('Tunnel-Type', 0, 64, 'tagint', 'VLAN (13) to put the person in a VLAN (RFC 3580), with '
    'the two below.', 'VLAN', ['std', 'unifi', 'ios', 'aruba'],
    {1: 'PPTP', 2: 'L2F', 3: 'L2TP', 4: 'ATMP', 5: 'VTP', 6: 'AH', 7: 'IP', 8: 'MIN-IP',
     9: 'ESP', 10: 'GRE', 11: 'DVS', 12: 'IP-in-IP', 13: 'VLAN'})
_ra('Tunnel-Medium-Type', 0, 65, 'tagint', 'IEEE-802 (6) for a VLAN.', 'IEEE-802',
    ['std', 'unifi', 'ios', 'aruba'],
    {1: 'IPv4', 2: 'IPv6', 3: 'NSAP', 4: 'HDLC', 5: 'BBN-1822', 6: 'IEEE-802', 7: 'E.163',
     8: 'E.164', 9: 'F.69', 10: 'X.121', 11: 'IPX', 12: 'Appletalk', 13: 'DecNet-IV',
     14: 'Banyan-Vines', 15: 'E.164-NSAP'})
_ra('Tunnel-Private-Group-Id', 0, 81, 'tagstr', 'The VLAN: its number or name.', '120',
    ['std', 'unifi', 'ios', 'aruba'])
# ---- Cisco ASA / FTD (3076) ----
_ra('ASA-Group-Policy', 3076, 25, 'string', 'The group policy the session gets.', 'GP_FULL', ['asa'])
_ra('ASA-Tunnel-Group-Lock', 3076, 85, 'string', 'Only this connection profile may be used.',
    'TG-Employees', ['asa'])
_ra('ASA-Simultaneous-Logins', 3076, 2, 'integer', 'Most sessions at once.', '1', ['asa'])
_ra('ASA-Primary-DNS', 3076, 5, 'ipaddr', 'DNS server pushed to the client.', '10.0.0.53', ['asa'])
_ra('ASA-Secondary-DNS', 3076, 6, 'ipaddr', 'Second DNS server.', '10.0.0.54', ['asa'])
_ra('ASA-Tunneling-Protocols', 3076, 11, 'integer', 'Allowed VPN types, a sum of: 4 IKEv1, '
    '8 L2TP/IPsec, 16 clientless, 32 AnyConnect SSL, 64 IKEv2.', '96', ['asa'])
_ra('ASA-Banner1', 3076, 15, 'string', 'Banner shown after sign-in.', 'Authorized use only',
    ['asa'])
_ra('ASA-Banner2', 3076, 36, 'string', 'Its continuation.', 'Contact IT x1234', ['asa'])
_ra('ASA-IPsec-Split-Tunnel-List', 3076, 27, 'string', 'Split-tunnel ACL name.', 'SPLIT-ACL',
    ['asa'])
_ra('ASA-IPsec-Default-Domain', 3076, 28, 'string', 'Default DNS domain.', 'corp.example.com',
    ['asa'])
_ra('ASA-IPsec-Split-DNS-Names', 3076, 29, 'string', 'Domains resolved through the tunnel.',
    'corp.example.com,lab.example.com', ['asa'])
_ra('ASA-Authenticated-User-Idle-Timeout', 3076, 50, 'integer', 'Idle minutes.', '30', ['asa'])
_ra('ASA-IPsec-Split-Tunneling-Policy', 3076, 55, 'integer', 'Split tunnelling.',
    'Split-Tunneling', ['asa'], {0: 'No-Split-Tunneling', 1: 'Split-Tunneling',
                                 2: 'Local-LAN-Permitted'})
_ra('ASA-WebVPN-Access-List', 3076, 73, 'string', 'Clientless ACL.', 'WEBVPN-ACL', ['asa'])
_ra('ASA-Access-List-Inbound', 3076, 86, 'string', 'Inbound filter ACL (FTD).', 'ACL-IN-ENG',
    ['asa'])
_ra('ASA-Access-List-Outbound', 3076, 87, 'string', 'Outbound filter ACL (FTD).', 'ACL-OUT-ENG',
    ['asa'])
_ra('ASA-VLAN', 3076, 140, 'integer', 'VLAN of the session, 0-4094.', '120', ['asa'])
_ra('ASA-Member-Of', 3076, 145, 'string', 'Groups for DAP rules only (sets no policy).',
    'Engineering,Sales', ['asa'])
_ra('ASA-Address-Pools', 3076, 217, 'string', 'Address pool name.', 'POOL-ENG', ['asa'])
_ra('ASA-IPv6-Address-Pools', 3076, 218, 'string', 'IPv6 pool name.', 'POOL6-ENG', ['asa'])
_ra('ASA-IPv6-VPN-Filter', 3076, 219, 'string', 'IPv6 filter ACL.', 'ACL6-ENG', ['asa'])
_ra('ASA-Privilege-Level', 3076, 220, 'integer', 'Management privilege level, 0-15.', '15',
    ['asa'])
_ra('ASA-SVC-Profiles', 3076, 128, 'string', 'AnyConnect profile.', 'AC-Profile-Eng', ['asa'])
# ---- Cisco (9) ----
_ra('Cisco-AVPair', 9, 1, 'string', 'proto:attr=value; may be given several times.',
    'shell:priv-lvl=15', ['ios', 'asa'])
# ---- Fortinet (12356) ----
_ra('Fortinet-Group-Name', 12356, 1, 'string', 'Matched by a user group\'s "match group-name".',
    'VPN-Engineering', ['forti'])
_ra('Fortinet-Vdom-Name', 12356, 3, 'string', 'VDOM of a wildcard RADIUS admin.', 'root',
    ['forti'])
_ra('Fortinet-Access-Profile', 12356, 6, 'string', 'Admin profile of a wildcard RADIUS admin.',
    'super_admin', ['forti'])
_ra('Fortinet-Client-IP-Address', 12356, 2, 'ipaddr', 'Client address (RSSO).', '10.212.134.200',
    ['forti'])
_ra('Fortinet-Interface-Name', 12356, 5, 'string', 'Interface name.', 'port1', ['forti'])
# ---- Palo Alto (25461) ----
_ra('PaloAlto-User-Group', 25461, 5, 'string', 'Group for the authentication profile\'s allow '
    'list / GlobalProtect config.', 'gp-engineering', ['pan'])
_ra('PaloAlto-Admin-Role', 25461, 1, 'string', 'Admin role (superuser or a role of your own).',
    'superuser', ['pan'])
_ra('PaloAlto-Admin-Access-Domain', 25461, 2, 'string', 'Admin access domain.', 'vsys1-domain',
    ['pan'])
_ra('PaloAlto-Panorama-Admin-Role', 25461, 3, 'string', 'Panorama admin role.', 'panorama-admin',
    ['pan'])
_ra('PaloAlto-Panorama-Admin-Access-Domain', 25461, 4, 'string', 'Panorama access domain.',
    'DG-Branch', ['pan'])
# ---- Check Point (2620) ----
_ra('CP-Gaia-User-Role', 2620, 229, 'string', 'Gaia roles, by commas.', 'adminrole', ['cp'])
_ra('CP-Gaia-SuperUser-Access', 2620, 230, 'integer', '1: superuser (UID 0) shell.', '1', ['cp'],
    {0: 'No', 1: 'Yes'})
# ---- Juniper (2636) ----
_ra('Juniper-Local-User-Name', 2636, 1, 'string', 'Template user whose login class applies.',
    'super-user-template', ['juniper'])
_ra('Juniper-Allow-Commands', 2636, 2, 'string', 'Commands allowed (regex).', '^(show|ping).*',
    ['juniper'])
_ra('Juniper-Deny-Commands', 2636, 3, 'string', 'Commands refused (regex).', '^request.*',
    ['juniper'])
_ra('Juniper-User-Permissions', 2636, 10, 'string', 'Permission bits.', 'view configure',
    ['juniper'])
_ra('Juniper-Ip-Pool-Name', 2636, 36, 'string', 'Address pool.', 'vpn-pool', ['juniper'])
_ra('Juniper-Local-Group-Name', 2636, 46, 'string', 'Local group (dynamic VPN).',
    'dynamic-vpn-users', ['juniper'])
# ---- Citrix NetScaler group extraction (3845) ----
_ra('Citrix-NS-User-Groups', 3845, 1, 'string', 'Groups for NetScaler group extraction '
    '(vendor 3845, type 1 - as set on the radiusAction); several by its separator.',
    'Engineering', ['citrix'])
# ---- F5 (3375) ----
_ra('F5-LTM-User-Role', 3375, 1, 'integer', 'Admin role on BIG-IP.', 'Administrator', ['f5'],
    {0: 'Administrator', 20: 'Resource-Admin', 40: 'User-Manager', 80: 'Auditor',
     100: 'Manager', 300: 'App-Editor', 350: 'Advanced-Operator', 400: 'Operator',
     450: 'Firewall-Manager', 480: 'Fraud-Protection-Manager', 500: 'Certificate-Manager',
     510: 'IRule-Manager', 700: 'Guest', 800: 'Web-Application-Security-Administrator',
     810: 'Web-Application-Security-Editor', 850: 'Acceleration-Policy-Editor',
     900: 'No-Access'})
_ra('F5-LTM-User-Role-Universal', 3375, 2, 'integer', 'The role in every partition.', 'Enabled',
    ['f5'], {0: 'Disabled', 1: 'Enabled'})
_ra('F5-LTM-User-Partition', 3375, 3, 'string', 'Partition (or all).', 'Common', ['f5'])
_ra('F5-LTM-User-Console', 3375, 4, 'integer', 'Shell access.', 'Enabled', ['f5'],
    {0: 'Disabled', 1: 'Enabled'})
_ra('F5-LTM-User-Shell', 3375, 5, 'string', 'disable, tmsh or bpsh.', 'tmsh', ['f5'])
# ---- SonicWall (8741) ----
_ra('SonicWall-User-Group', 8741, 3, 'string', 'A SonicOS local group.', 'SSLVPN Services',
    ['sonic'])
_ra('SonicWall-User-Privilege', 8741, 1, 'integer', 'Privilege.', 'VPN-Client-Access', ['sonic'],
    {1: 'Remote-Access', 2: 'Bypass-Filters', 3: 'VPN-Client-Access', 4: 'Access-To-VPN',
     5: 'Limited-Management', 6: 'L2TP-Client-Access', 7: 'Wireless-Guest',
     8: 'Wireless-Add-ACL', 9: 'Internet-Access'})
# ---- Aruba (14823) ----
_ra('Aruba-User-Role', 14823, 1, 'string', 'Role on the controller / AOS-CX.', 'employee',
    ['aruba'])
_ra('Aruba-User-Vlan', 14823, 2, 'integer', 'VLAN number.', '120', ['aruba'])
_ra('Aruba-Admin-Role', 14823, 4, 'string', 'Management role.', 'root', ['aruba'])
_ra('Aruba-Named-User-Vlan', 14823, 9, 'string', 'VLAN by name.', 'staff-vlan', ['aruba'])
# ---- MikroTik (14988) ----
_ra('Mikrotik-Group', 14988, 3, 'string', 'User group (router login) or PPP profile.', 'full',
    ['mikrotik'])
_ra('Mikrotik-Rate-Limit', 14988, 8, 'string', 'rx/tx [burst...].', '10M/20M', ['mikrotik'])
_ra('Mikrotik-Address-List', 14988, 19, 'string', 'Address list the client is put on.',
    'vpn-staff', ['mikrotik'])
_ra('Mikrotik-Wireless-VLANID', 14988, 26, 'integer', 'Wireless VLAN.', '120', ['mikrotik'])
# ---- Microsoft (311) ----
_ra('MS-Primary-DNS-Server', 311, 28, 'ipaddr', 'DNS server (PPP/L2TP).', '10.0.0.53', ['ms'])
_ra('MS-Secondary-DNS-Server', 311, 29, 'ipaddr', 'Second DNS server.', '10.0.0.54', ['ms'])
_ra('MS-MPPE-Encryption-Policy', 311, 7, 'integer', 'MPPE encryption.', 'Encryption-Required',
    ['ms'], {1: 'Encryption-Allowed', 2: 'Encryption-Required'})
# ---- pfSense (13644) ----
_ra('pfSense-Bandwidth-Max-Up', 13644, 1, 'integer', 'Upload limit (Kbit/s).', '10000',
    ['pfsense'])
_ra('pfSense-Bandwidth-Max-Down', 13644, 2, 'integer', 'Download limit (Kbit/s).', '20000',
    ['pfsense'])
# ---- Zyxel (890) ----
_ra('Zyxel-Privilege-AVPair', 890, 3, 'string', 'Admin privilege pair.', 'shell:priv-lvl=2',
    ['zyxel'])

REPLY_CATALOG = _R
VENDORS.update({9: 'Cisco', 311: 'Microsoft', 890: 'Zyxel', 2620: 'Check Point', 2636: 'Juniper',
                3076: 'Cisco-ASA', 3375: 'F5', 3845: 'Citrix-NetScaler', 8741: 'SonicWall',
                12356: 'Fortinet', 13644: 'pfSense', 14823: 'Aruba', 14988: 'Mikrotik',
                25461: 'PaloAlto'})
for _a in REPLY_CATALOG:
    if _a['values']:
        RADIUS_VALUES.setdefault(_a['name'], {}).update(_a['values'])
    if _a['vendor']:
        VSA_ATTRS[(_a['vendor'], _a['num'])] = (_a['name'], _a['type'])
VSA_NUMBERS = {v[0].lower(): (k, v[1]) for k, v in VSA_ATTRS.items()}
REPLY_ATTRS = tuple(a['name'] for a in REPLY_CATALOG)
# Spellings that are taken too.
RADIUS_VALUE_ALIASES = {'Tunnel-Medium-Type': {'802': 6}}

# Lines ready to be put in, for the common cases.
REPLY_SNIPPETS = [
    {'name': 'VLAN', 'products': ['std', 'unifi', 'ios', 'aruba'],
     'lines': ['Tunnel-Type = VLAN', 'Tunnel-Medium-Type = IEEE-802',
               'Tunnel-Private-Group-Id = 120']},
    {'name': 'Cisco ASA: group policy', 'products': ['asa'],
     'lines': ['ASA-Group-Policy = GP_FULL']},
    {'name': 'Cisco ASA: group policy, the old way', 'products': ['asa'],
     'lines': ['Class = OU=GP_FULL;']},
    {'name': 'Cisco ASA: lock to a connection profile', 'products': ['asa'],
     'lines': ['ASA-Group-Policy = GP_FULL', 'ASA-Tunnel-Group-Lock = TG-Employees']},
    {'name': 'Cisco IOS/NX-OS: admin', 'products': ['ios'],
     'lines': ['Service-Type = Administrative-User', 'Cisco-AVPair = shell:priv-lvl=15']},
    {'name': 'FortiGate: user group', 'products': ['forti'],
     'lines': ['Fortinet-Group-Name = VPN-Engineering']},
    {'name': 'FortiGate: wildcard admin', 'products': ['forti'],
     'lines': ['Fortinet-Access-Profile = super_admin', 'Fortinet-Vdom-Name = root']},
    {'name': 'Palo Alto: GlobalProtect group', 'products': ['pan'],
     'lines': ['PaloAlto-User-Group = gp-engineering']},
    {'name': 'Palo Alto: admin', 'products': ['pan'],
     'lines': ['PaloAlto-Admin-Role = superuser']},
    {'name': 'Citrix NetScaler: group', 'products': ['citrix'],
     'lines': ['Citrix-NS-User-Groups = Engineering']},
    {'name': 'F5 BIG-IP: admin', 'products': ['f5'],
     'lines': ['F5-LTM-User-Role = Administrator', 'F5-LTM-User-Partition = all',
               'F5-LTM-User-Shell = tmsh']},
    {'name': 'SonicWall: group', 'products': ['sonic'],
     'lines': ['SonicWall-User-Group = SSLVPN Services']},
    {'name': 'WatchGuard / Sophos: group', 'products': ['watchguard', 'sophos'],
     'lines': ['Filter-Id = VPN-Users']},
    {'name': 'OpenVPN Access Server: group', 'products': ['openvpn'],
     'lines': ['Framed-Pool = staff']},
    {'name': 'Ivanti / Pulse: role', 'products': ['ivanti'], 'lines': ['Class = Engineering']},
    {'name': 'Aruba: role', 'products': ['aruba'], 'lines': ['Aruba-User-Role = employee']},
    {'name': 'MikroTik: speed', 'products': ['mikrotik'],
     'lines': ['Mikrotik-Rate-Limit = 10M/20M']},
    {'name': 'Check Point Gaia: admin', 'products': ['cp'],
     'lines': ['CP-Gaia-User-Role = adminrole', 'CP-Gaia-SuperUser-Access = 1']},
    {'name': 'Juniper: login class', 'products': ['juniper'],
     'lines': ['Juniper-Local-User-Name = super-user-template']},
    {'name': 'Session limits', 'products': ['std'],
     'lines': ['Session-Timeout = 43200', 'Idle-Timeout = 1800']},
]


def reply_catalogue():
    """The catalogue for the pages: attributes, products, snippets."""
    return {'attrs': [dict(a, vendor_name=VENDORS.get(a['vendor'], '') if a['vendor'] else '',
                           values=[v for _k, v in sorted(a['values'].items())])
                      for a in REPLY_CATALOG],
            'products': REPLY_PRODUCTS, 'product_says': REPLY_PRODUCT_SAYS,
            'snippets': REPLY_SNIPPETS}


