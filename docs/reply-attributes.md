# The answer: attributes for each product

What a realm or a group sends back with an Access-Accept is written a line each, `Name = value`, in Settings → Realms. On the page, **Ctrl+Space** lists the attributes below (for the product chosen above the box), and after `=` the values a numbered one takes; every line is checked as it is typed. Any attribute not listed can still be sent as `Vendor-<vendor>-Attr-<number> = value` (a string, or `0x…` bytes).

Names are FreeRADIUS's (v3 dictionaries). Tagged attributes (Tunnel-*) are sent with tag 0.

## Standard (RFC)

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Reply-Message` | RFC / 18 | string | Text shown to the person (a challenge's prompt). | `Welcome` |
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |
| `Session-Timeout` | RFC / 27 | integer | Longest session, in seconds. | `43200` |
| `Idle-Timeout` | RFC / 28 | integer | Seconds without traffic before it ends. | `1800` |
| `Service-Type` | RFC / 6 | integer | The kind of service; Administrative-User or NAS-Prompt-User for logins to the device itself. Values: Login-User, Framed-User, Callback-Login-User, Callback-Framed-User, Outbound-User, Administrative-User, NAS-Prompt-User, Authenticate-Only, Callback-NAS-Prompt, Call-Check, Callback-Administrative | `Administrative-User` |
| `Framed-Protocol` | RFC / 7 | integer | Framing of a PPP/L2TP session. Values: PPP, SLIP, ARAP, Gandalf-SLML, Xylogics-IPX-SLIP, X.75-Synchronous | `PPP` |
| `Framed-IP-Address` | RFC / 8 | ipaddr | A fixed address for this person's tunnel. | `10.10.20.15` |
| `Framed-IP-Netmask` | RFC / 9 | ipaddr | Its netmask. | `255.255.255.0` |
| `Framed-Route` | RFC / 22 | string | A route pushed for this person. | `192.168.50.0/24 0.0.0.0 1` |
| `Framed-MTU` | RFC / 12 | integer | MTU of the tunnel. | `1400` |
| `Framed-Pool` | RFC / 88 | string | Name of an address pool; the group for OpenVPN Access Server. | `vpn-pool-staff` |
| `Acct-Interim-Interval` | RFC / 85 | integer | Seconds between interim accounting updates. | `600` |
| `Termination-Action` | RFC / 29 | integer | Ask again when the session times out (802.1X). Values: Default, RADIUS-Request | `RADIUS-Request` |
| `Port-Limit` | RFC / 62 | integer | Most ports/links at once. | `1` |
| `Tunnel-Type` | RFC / 64 | tagint | VLAN (13) to put the person in a VLAN (RFC 3580), with the two below. Values: PPTP, L2F, L2TP, ATMP, VTP, AH, IP, MIN-IP, ESP, GRE, DVS, IP-in-IP, VLAN | `VLAN` |
| `Tunnel-Medium-Type` | RFC / 65 | tagint | IEEE-802 (6) for a VLAN. Values: IPv4, IPv6, NSAP, HDLC, BBN-1822, IEEE-802, E.163, E.164, F.69, X.121, IPX, Appletalk, DecNet-IV, Banyan-Vines, E.164-NSAP | `IEEE-802` |
| `Tunnel-Private-Group-Id` | RFC / 81 | tagstr | The VLAN: its number or name. | `120` |

**VLAN**

```
Tunnel-Type = VLAN
Tunnel-Medium-Type = IEEE-802
Tunnel-Private-Group-Id = 120
```

**Session limits**

```
Session-Timeout = 43200
Idle-Timeout = 1800
```

## Cisco ASA / FTD (AnyConnect, Secure Client)

Group policy: ASA-Group-Policy = name (preferred since 8.2; FTD takes name or OU=name). Older: Class = OU=name;. DAP rules can read ASA-Member-Of or Class.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |
| `Service-Type` | RFC / 6 | integer | The kind of service; Administrative-User or NAS-Prompt-User for logins to the device itself. Values: Login-User, Framed-User, Callback-Login-User, Callback-Framed-User, Outbound-User, Administrative-User, NAS-Prompt-User, Authenticate-Only, Callback-NAS-Prompt, Call-Check, Callback-Administrative | `Administrative-User` |
| `Framed-IP-Address` | RFC / 8 | ipaddr | A fixed address for this person's tunnel. | `10.10.20.15` |
| `Framed-IP-Netmask` | RFC / 9 | ipaddr | Its netmask. | `255.255.255.0` |
| `ASA-Group-Policy` | Cisco-ASA 3076 / 25 | string | The group policy the session gets. | `GP_FULL` |
| `ASA-Tunnel-Group-Lock` | Cisco-ASA 3076 / 85 | string | Only this connection profile may be used. | `TG-Employees` |
| `ASA-Simultaneous-Logins` | Cisco-ASA 3076 / 2 | integer | Most sessions at once. | `1` |
| `ASA-Primary-DNS` | Cisco-ASA 3076 / 5 | ipaddr | DNS server pushed to the client. | `10.0.0.53` |
| `ASA-Secondary-DNS` | Cisco-ASA 3076 / 6 | ipaddr | Second DNS server. | `10.0.0.54` |
| `ASA-Tunneling-Protocols` | Cisco-ASA 3076 / 11 | integer | Allowed VPN types, a sum of: 4 IKEv1, 8 L2TP/IPsec, 16 clientless, 32 AnyConnect SSL, 64 IKEv2. | `96` |
| `ASA-Banner1` | Cisco-ASA 3076 / 15 | string | Banner shown after sign-in. | `Authorized use only` |
| `ASA-Banner2` | Cisco-ASA 3076 / 36 | string | Its continuation. | `Contact IT x1234` |
| `ASA-IPsec-Split-Tunnel-List` | Cisco-ASA 3076 / 27 | string | Split-tunnel ACL name. | `SPLIT-ACL` |
| `ASA-IPsec-Default-Domain` | Cisco-ASA 3076 / 28 | string | Default DNS domain. | `corp.example.com` |
| `ASA-IPsec-Split-DNS-Names` | Cisco-ASA 3076 / 29 | string | Domains resolved through the tunnel. | `corp.example.com,lab.example.com` |
| `ASA-Authenticated-User-Idle-Timeout` | Cisco-ASA 3076 / 50 | integer | Idle minutes. | `30` |
| `ASA-IPsec-Split-Tunneling-Policy` | Cisco-ASA 3076 / 55 | integer | Split tunnelling. Values: No-Split-Tunneling, Split-Tunneling, Local-LAN-Permitted | `Split-Tunneling` |
| `ASA-WebVPN-Access-List` | Cisco-ASA 3076 / 73 | string | Clientless ACL. | `WEBVPN-ACL` |
| `ASA-Access-List-Inbound` | Cisco-ASA 3076 / 86 | string | Inbound filter ACL (FTD). | `ACL-IN-ENG` |
| `ASA-Access-List-Outbound` | Cisco-ASA 3076 / 87 | string | Outbound filter ACL (FTD). | `ACL-OUT-ENG` |
| `ASA-VLAN` | Cisco-ASA 3076 / 140 | integer | VLAN of the session, 0-4094. | `120` |
| `ASA-Member-Of` | Cisco-ASA 3076 / 145 | string | Groups for DAP rules only (sets no policy). | `Engineering,Sales` |
| `ASA-Address-Pools` | Cisco-ASA 3076 / 217 | string | Address pool name. | `POOL-ENG` |
| `ASA-IPv6-Address-Pools` | Cisco-ASA 3076 / 218 | string | IPv6 pool name. | `POOL6-ENG` |
| `ASA-IPv6-VPN-Filter` | Cisco-ASA 3076 / 219 | string | IPv6 filter ACL. | `ACL6-ENG` |
| `ASA-Privilege-Level` | Cisco-ASA 3076 / 220 | integer | Management privilege level, 0-15. | `15` |
| `ASA-SVC-Profiles` | Cisco-ASA 3076 / 128 | string | AnyConnect profile. | `AC-Profile-Eng` |
| `Cisco-AVPair` | Cisco 9 / 1 | string | proto:attr=value; may be given several times. | `shell:priv-lvl=15` |

**Cisco ASA: group policy**

```
ASA-Group-Policy = GP_FULL
```

**Cisco ASA: group policy, the old way**

```
Class = OU=GP_FULL;
```

**Cisco ASA: lock to a connection profile**

```
ASA-Group-Policy = GP_FULL
ASA-Tunnel-Group-Lock = TG-Employees
```

## Cisco IOS / ISE / NX-OS

Cisco-AVPair carries proto:attr=value pairs: shell:priv-lvl=15 for admins, ip:inacl#1=... per-user ACEs, ACS:CiscoSecure-Defined-ACL for an ISE dACL.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Service-Type` | RFC / 6 | integer | The kind of service; Administrative-User or NAS-Prompt-User for logins to the device itself. Values: Login-User, Framed-User, Callback-Login-User, Callback-Framed-User, Outbound-User, Administrative-User, NAS-Prompt-User, Authenticate-Only, Callback-NAS-Prompt, Call-Check, Callback-Administrative | `Administrative-User` |
| `Tunnel-Type` | RFC / 64 | tagint | VLAN (13) to put the person in a VLAN (RFC 3580), with the two below. Values: PPTP, L2F, L2TP, ATMP, VTP, AH, IP, MIN-IP, ESP, GRE, DVS, IP-in-IP, VLAN | `VLAN` |
| `Tunnel-Medium-Type` | RFC / 65 | tagint | IEEE-802 (6) for a VLAN. Values: IPv4, IPv6, NSAP, HDLC, BBN-1822, IEEE-802, E.163, E.164, F.69, X.121, IPX, Appletalk, DecNet-IV, Banyan-Vines, E.164-NSAP | `IEEE-802` |
| `Tunnel-Private-Group-Id` | RFC / 81 | tagstr | The VLAN: its number or name. | `120` |
| `Cisco-AVPair` | Cisco 9 / 1 | string | proto:attr=value; may be given several times. | `shell:priv-lvl=15` |

**VLAN**

```
Tunnel-Type = VLAN
Tunnel-Medium-Type = IEEE-802
Tunnel-Private-Group-Id = 120
```

**Cisco IOS/NX-OS: admin**

```
Service-Type = Administrative-User
Cisco-AVPair = shell:priv-lvl=15
```

## Fortinet FortiGate

A user group whose RADIUS server has "match group-name X" is matched by Fortinet-Group-Name = X. Wildcard admins: Fortinet-Access-Profile and -Vdom-Name.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Framed-IP-Address` | RFC / 8 | ipaddr | A fixed address for this person's tunnel. | `10.10.20.15` |
| `Fortinet-Group-Name` | Fortinet 12356 / 1 | string | Matched by a user group's "match group-name". | `VPN-Engineering` |
| `Fortinet-Vdom-Name` | Fortinet 12356 / 3 | string | VDOM of a wildcard RADIUS admin. | `root` |
| `Fortinet-Access-Profile` | Fortinet 12356 / 6 | string | Admin profile of a wildcard RADIUS admin. | `super_admin` |
| `Fortinet-Client-IP-Address` | Fortinet 12356 / 2 | ipaddr | Client address (RSSO). | `10.212.134.200` |
| `Fortinet-Interface-Name` | Fortinet 12356 / 5 | string | Interface name. | `port1` |

**FortiGate: user group**

```
Fortinet-Group-Name = VPN-Engineering
```

**FortiGate: wildcard admin**

```
Fortinet-Access-Profile = super_admin
Fortinet-Vdom-Name = root
```

## Palo Alto Networks

PaloAlto-User-Group = group, matched by the authentication profile's allow list or a GlobalProtect config. Admins: PaloAlto-Admin-Role.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `PaloAlto-User-Group` | PaloAlto 25461 / 5 | string | Group for the authentication profile's allow list / GlobalProtect config. | `gp-engineering` |
| `PaloAlto-Admin-Role` | PaloAlto 25461 / 1 | string | Admin role (superuser or a role of your own). | `superuser` |
| `PaloAlto-Admin-Access-Domain` | PaloAlto 25461 / 2 | string | Admin access domain. | `vsys1-domain` |
| `PaloAlto-Panorama-Admin-Role` | PaloAlto 25461 / 3 | string | Panorama admin role. | `panorama-admin` |
| `PaloAlto-Panorama-Admin-Access-Domain` | PaloAlto 25461 / 4 | string | Panorama access domain. | `DG-Branch` |

**Palo Alto: GlobalProtect group**

```
PaloAlto-User-Group = gp-engineering
```

**Palo Alto: admin**

```
PaloAlto-Admin-Role = superuser
```

## Check Point

Gaia admins: CP-Gaia-User-Role (and CP-Gaia-SuperUser-Access). Remote access VPN groups usually from Class.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `CP-Gaia-User-Role` | Check Point 2620 / 229 | string | Gaia roles, by commas. | `adminrole` |
| `CP-Gaia-SuperUser-Access` | Check Point 2620 / 230 | integer | 1: superuser (UID 0) shell. Values: No, Yes | `1` |

**Check Point Gaia: admin**

```
CP-Gaia-User-Role = adminrole
CP-Gaia-SuperUser-Access = 1
```

## Juniper (Junos)

Junos logins: Juniper-Local-User-Name = a template user (its login class).

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Juniper-Local-User-Name` | Juniper 2636 / 1 | string | Template user whose login class applies. | `super-user-template` |
| `Juniper-Allow-Commands` | Juniper 2636 / 2 | string | Commands allowed (regex). | `^(show|ping).*` |
| `Juniper-Deny-Commands` | Juniper 2636 / 3 | string | Commands refused (regex). | `^request.*` |
| `Juniper-User-Permissions` | Juniper 2636 / 10 | string | Permission bits. | `view configure` |
| `Juniper-Ip-Pool-Name` | Juniper 2636 / 36 | string | Address pool. | `vpn-pool` |
| `Juniper-Local-Group-Name` | Juniper 2636 / 46 | string | Local group (dynamic VPN). | `dynamic-vpn-users` |

**Juniper: login class**

```
Juniper-Local-User-Name = super-user-template
```

## Ivanti Connect Secure (Pulse)

Role mapping can read any attribute: Class or Filter-Id = role name is usual. Framed-IP-Address for a fixed address.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Reply-Message` | RFC / 18 | string | Text shown to the person (a challenge's prompt). | `Welcome` |
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |
| `Framed-IP-Address` | RFC / 8 | ipaddr | A fixed address for this person's tunnel. | `10.10.20.15` |

**Ivanti / Pulse: role**

```
Class = Engineering
```

## Citrix NetScaler / ADC Gateway

Group extraction reads a vendor attribute set on the radiusAction (groupVendorIdentifier 3845, groupAttributeType 1): Citrix-NS-User-Groups.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Citrix-NS-User-Groups` | Citrix-NetScaler 3845 / 1 | string | Groups for NetScaler group extraction (vendor 3845, type 1 - as set on the radiusAction); several by its separator. | `Engineering` |

**Citrix NetScaler: group**

```
Citrix-NS-User-Groups = Engineering
```

## F5 BIG-IP

Admins: F5-LTM-User-Role (+ -Partition, -Shell). APM can branch on any attribute (session.radius.last.attr.class).

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `F5-LTM-User-Role` | F5 3375 / 1 | integer | Admin role on BIG-IP. Values: Administrator, Resource-Admin, User-Manager, Auditor, Manager, App-Editor, Advanced-Operator, Operator, Firewall-Manager, Fraud-Protection-Manager, Certificate-Manager, IRule-Manager, Guest, Web-Application-Security-Administrator, Web-Application-Security-Editor, Acceleration-Policy-Editor, No-Access | `Administrator` |
| `F5-LTM-User-Role-Universal` | F5 3375 / 2 | integer | The role in every partition. Values: Disabled, Enabled | `Enabled` |
| `F5-LTM-User-Partition` | F5 3375 / 3 | string | Partition (or all). | `Common` |
| `F5-LTM-User-Console` | F5 3375 / 4 | integer | Shell access. Values: Disabled, Enabled | `Enabled` |
| `F5-LTM-User-Shell` | F5 3375 / 5 | string | disable, tmsh or bpsh. | `tmsh` |

**F5 BIG-IP: admin**

```
F5-LTM-User-Role = Administrator
F5-LTM-User-Partition = all
F5-LTM-User-Shell = tmsh
```

## SonicWall

SonicWall-User-Group = a SonicOS group (or Filter-Id, by the RADIUS settings).

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |
| `SonicWall-User-Group` | SonicWall 8741 / 3 | string | A SonicOS local group. | `SSLVPN Services` |
| `SonicWall-User-Privilege` | SonicWall 8741 / 1 | integer | Privilege. Values: Remote-Access, Bypass-Filters, VPN-Client-Access, Access-To-VPN, Limited-Management, L2TP-Client-Access, Wireless-Guest, Wireless-Add-ACL, Internet-Access | `VPN-Client-Access` |

**SonicWall: group**

```
SonicWall-User-Group = SSLVPN Services
```

## Aruba (HPE)

Aruba-User-Role = a role of the controller; or a VLAN.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Tunnel-Type` | RFC / 64 | tagint | VLAN (13) to put the person in a VLAN (RFC 3580), with the two below. Values: PPTP, L2F, L2TP, ATMP, VTP, AH, IP, MIN-IP, ESP, GRE, DVS, IP-in-IP, VLAN | `VLAN` |
| `Tunnel-Medium-Type` | RFC / 65 | tagint | IEEE-802 (6) for a VLAN. Values: IPv4, IPv6, NSAP, HDLC, BBN-1822, IEEE-802, E.163, E.164, F.69, X.121, IPX, Appletalk, DecNet-IV, Banyan-Vines, E.164-NSAP | `IEEE-802` |
| `Tunnel-Private-Group-Id` | RFC / 81 | tagstr | The VLAN: its number or name. | `120` |
| `Aruba-User-Role` | Aruba 14823 / 1 | string | Role on the controller / AOS-CX. | `employee` |
| `Aruba-User-Vlan` | Aruba 14823 / 2 | integer | VLAN number. | `120` |
| `Aruba-Admin-Role` | Aruba 14823 / 4 | string | Management role. | `root` |
| `Aruba-Named-User-Vlan` | Aruba 14823 / 9 | string | VLAN by name. | `staff-vlan` |

**VLAN**

```
Tunnel-Type = VLAN
Tunnel-Medium-Type = IEEE-802
Tunnel-Private-Group-Id = 120
```

**Aruba: role**

```
Aruba-User-Role = employee
```

## MikroTik

Mikrotik-Group for router logins, Mikrotik-Rate-Limit for speed, Framed-Pool for PPP.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Framed-IP-Address` | RFC / 8 | ipaddr | A fixed address for this person's tunnel. | `10.10.20.15` |
| `Framed-Pool` | RFC / 88 | string | Name of an address pool; the group for OpenVPN Access Server. | `vpn-pool-staff` |
| `Mikrotik-Group` | Mikrotik 14988 / 3 | string | User group (router login) or PPP profile. | `full` |
| `Mikrotik-Rate-Limit` | Mikrotik 14988 / 8 | string | rx/tx [burst...]. | `10M/20M` |
| `Mikrotik-Address-List` | Mikrotik 14988 / 19 | string | Address list the client is put on. | `vpn-staff` |
| `Mikrotik-Wireless-VLANID` | Mikrotik 14988 / 26 | integer | Wireless VLAN. | `120` |

**MikroTik: speed**

```
Mikrotik-Rate-Limit = 10M/20M
```

## Microsoft (RRAS)

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `MS-Primary-DNS-Server` | Microsoft 311 / 28 | ipaddr | DNS server (PPP/L2TP). | `10.0.0.53` |
| `MS-Secondary-DNS-Server` | Microsoft 311 / 29 | ipaddr | Second DNS server. | `10.0.0.54` |
| `MS-MPPE-Encryption-Policy` | Microsoft 311 / 7 | integer | MPPE encryption. Values: Encryption-Allowed, Encryption-Required | `Encryption-Required` |

## pfSense

Bandwidth by pfSense-Bandwidth-Max-Up/-Down; groups usually by Class.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `pfSense-Bandwidth-Max-Up` | pfSense 13644 / 1 | integer | Upload limit (Kbit/s). | `10000` |
| `pfSense-Bandwidth-Max-Down` | pfSense 13644 / 2 | integer | Download limit (Kbit/s). | `20000` |

## WatchGuard Firebox

The only group attribute read is Filter-Id = group.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |

**WatchGuard / Sophos: group**

```
Filter-Id = VPN-Users
```

## Sophos Firewall

The group comes from the attribute set as "Group name attribute": Filter-Id or Class.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |
| `Filter-Id` | RFC / 11 | string | Name of a filter/ACL or of a group (WatchGuard, SonicWall, Sophos, ASA ACL). | `VPN-Admins` |

**WatchGuard / Sophos: group**

```
Filter-Id = VPN-Users
```

## OpenVPN Access Server

The group comes from Framed-Pool (the post-auth script).

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Framed-Pool` | RFC / 88 | string | Name of an address pool; the group for OpenVPN Access Server. | `vpn-pool-staff` |

**OpenVPN Access Server: group**

```
Framed-Pool = staff
```

## Ubiquiti UniFi

VLAN by the standard three: Tunnel-Type = VLAN, Tunnel-Medium-Type = IEEE-802, Tunnel-Private-Group-Id = the VLAN.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Tunnel-Type` | RFC / 64 | tagint | VLAN (13) to put the person in a VLAN (RFC 3580), with the two below. Values: PPTP, L2F, L2TP, ATMP, VTP, AH, IP, MIN-IP, ESP, GRE, DVS, IP-in-IP, VLAN | `VLAN` |
| `Tunnel-Medium-Type` | RFC / 65 | tagint | IEEE-802 (6) for a VLAN. Values: IPv4, IPv6, NSAP, HDLC, BBN-1822, IEEE-802, E.163, E.164, F.69, X.121, IPX, Appletalk, DecNet-IV, Banyan-Vines, E.164-NSAP | `IEEE-802` |
| `Tunnel-Private-Group-Id` | RFC / 81 | tagstr | The VLAN: its number or name. | `120` |

**VLAN**

```
Tunnel-Type = VLAN
Tunnel-Medium-Type = IEEE-802
Tunnel-Private-Group-Id = 120
```

## Omnissa (VMware) Horizon UAG

Only Accept or Reject is used - no attribute is read. A challenge shows Reply-Message as its prompt. Entitlements come from Active Directory.

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Reply-Message` | RFC / 18 | string | Text shown to the person (a challenge's prompt). | `Welcome` |

## Barracuda CloudGen

The group is read from Class or Filter-Id (parsed by its delimiter).

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Class` | RFC / 25 | string | A tag the NAS keeps and echoes in accounting; the group or policy for ASA (OU=name;), Sophos, Ivanti, Barracuda, F5 APM. | `OU=GP_FULL;` |

## Zyxel

| Attribute | Vendor / number | Type | What it does | Example |
|---|---|---|---|---|
| `Zyxel-Privilege-AVPair` | Zyxel 890 / 3 | string | Admin privilege pair. | `shell:priv-lvl=2` |

