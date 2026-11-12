# FortiGate (FortiOS 6.0 - 6.4) - setup for acme

acme talks to the FortiGate through the **FortiOS REST API** with an **API token** (`Authorization: Bearer <token>`, HTTPS only). It imports the certificate under a dated name (`acme-<name>-<date>-<serial>`, at most 35 characters) through `POST /api/v2/monitor/vpn-certificate/local/import` (PKCS#12 with a one-time password, or certificate + key PEM), imports the intermediates as CA certificates, points the services you ticked at it and deletes older acme certificates beyond *keep*.

## Which FortiOS this guide is for

Module version **"FortiOS 6.0 - 6.4"** (`6.0`): FortiOS **6.0.x, 6.2.x and 6.4.x**. On another FortiOS acme refuses to deploy (before changing anything) and says which version of the target to choose.

| Module version | FortiOS | Inspection profile `server-cert` | VIP `ssl-certificate` |
|---|---|---|---|
| any version (detects it) | 6.0 - 8.0 | by version | by version |
| FortiOS 6.0 - 6.4 | 6.0.x - 6.4.x | a name | a name |
| FortiOS 7.0 - 7.4.1 | 7.0.0 - 7.4.1 | a list of `{name}` | a name |
| FortiOS 7.4.2 - 8.0 | 7.4.2 - 8.0 | a list of `{name}` | a list of `{name}` |

Everything else acme uses - the certificate import, `system global admin-server-cert`, `vpn ssl settings servercert`, deleting `vpn.certificate/local` - is the same in 6.0 - 8.0 (Fortinet's Ansible collection 2.6.0, which lists the FortiOS versions of each attribute, and schemas read from FortiOS 7.4.8). Not sure which FortiOS runs on the box? `get system status` on the CLI, or *Find the settings from the account* in acme shows the version and the module version for it.

## What acme changes on the FortiGate

| acme option | FortiOS setting | Value |
|---|---|---|
| (always) | `config vpn certificate local` | a new local certificate `acme-...`; older `acme-...` ones of the same certificate deleted beyond *keep* (one still in use stays) |
| Import the intermediates as CA certificates (advanced, on) | `config vpn certificate ca` | the intermediate CA(s), global scope; one already there is skipped |
| Admin GUI certificate | `config system global` / `set admin-server-cert` | the new certificate (global - needs the certificate imported in *global* scope) |
| SSL VPN certificate | `config vpn ssl settings` / `set servercert` | the new certificate, in the VDOM |
| SSL/SSH inspection profiles | `config firewall ssl-ssh-profile` / `set server-cert` | a single name (`server-cert` is one certificate in 6.x) - the profile's certificate is replaced |
| Virtual IPs | `config firewall vip` / `set ssl-certificate` | a single name |

acme does not create profiles, VIPs or the SSL VPN itself, and does not switch an inspection profile to `server-cert-mode replace` - set that up once yourself.

## Set up the FortiGate

You need a *super_admin* to create the profile and the API user (only a super admin may create or change an API admin).

### 1. An admin profile with the least rights acme needs

| What acme does | Permission group (accprofile) | Needed |
|---|---|---|
| Read the version (`monitor/system/status`) | any | always |
| Import / delete certificates, CA import, SSL VPN `servercert` | `vpngrp` read-write | always (the 6.0.4 REST reference gives `vpngrp` as the access group of the certificate imports) |
| Admin GUI certificate (`system global`) | `sysgrp` custom, `cfg` read-write | when *Admin GUI* is ticked |
| Virtual IPs (`firewall vip`) | `fwgrp` read-write | when VIPs are listed |
| SSL/SSH inspection profiles (`firewall ssl-ssh-profile`) | `utmgrp` read-write (Security Profiles) | when profiles are listed |

```text
config system accprofile
    edit "acme-cert"
        set comments "acme: certificates, admin GUI, SSL VPN, inspection profiles, VIPs"
        set scope global
        set secfabgrp none
        set ftviewgrp none
        set authgrp none
        set sysgrp custom
        set netgrp none
        set loggrp none
        set fwgrp read-write
        set vpngrp read-write
        set utmgrp read-write
        set wifi none
        config sysgrp-permission
            set admin none
            set upd none
            set cfg read-write
            set mnt none
        end
    next
end
```

- `set scope global` lets the API user import into the **global** scope (the default of acme, needed for the admin GUI): the REST reference says global scope is only for global administrators. Without VDOMs the line is harmless; if you import into the VDOM only (*Import into: the VDOM*) and do not set the admin GUI, `scope vdom` is enough.
- Leave out what you do not use: no VIPs - `set fwgrp none`; no inspection profiles - `set utmgrp none`; no admin GUI - `set sysgrp none` (*uncertain*: on some versions the certificate store may also be checked against `sysgrp cfg` - if an import answers 403 with `vpngrp` read-write, give `cfg` read-write back).

### 2. The REST API admin, its trusted hosts and the token

Put the address(es) of the acme server(s) - every node of a cluster - into the trusted hosts: at least one trusted host is required, and a request from anywhere else is refused.

```text
config system api-user
    edit "acme"
        set comments "acme certificate manager"
        set accprofile "acme-cert"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.0.2.10 255.255.255.255
            next
        end
    next
end
```

- `192.0.2.10` is an example - use acme's address (`ipv6-trusthost` for IPv6, another `edit 2` for a second node).
- `set vdom "root"`: the VDOM the API user works in; with VDOMs list the VDOM(s) of the SSL VPN, profiles and VIPs.
- Leave `peer-auth` disabled (acme sends no client certificate) and `cors-allow-origin` empty.

Generate the token - it is shown **once**:

```text
execute api-user generate-key acme
```

In the GUI the same is *System → Administrators → Create New → REST API Admin* (profile `acme-cert`, *Trusted Hosts*, then the token shown on *OK*). A new key replaces the old one.

### 3. VDOMs

- Without VDOMs: leave acme's *VDOM* empty (or `root`).
- With VDOMs: acme sends `?vdom=<VDOM>` (the target's VDOM, or the deployment's). The SSL VPN, inspection profiles and VIPs are per VDOM; the admin GUI certificate is global.
- *Import into: global* (default) makes the certificate usable in every VDOM and by the admin GUI; it needs the `scope global` profile. *the VDOM* imports it only there.

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **FortiOS 6.0 - 6.4** |
| Address / HTTPS port | the FortiGate's management address and admin HTTPS port (`admin-sport`, default 443) |
| API token | the key from `execute api-user generate-key` |
| VDOM | `root`, your VDOM, or empty without VDOMs |
| Check the device's certificate | on; off only while the FortiGate still has its self-signed `Fortinet_GUI_Server` |
| Admin GUI / SSL VPN certificate (deploy) | tick what should use the certificate |
| SSL/SSH inspection profiles, Virtual IPs (deploy) | one name a line, e.g. `inbound-replace`, `vip-www` |
| Previous versions to keep (advanced) | older acme certificates to keep (one still referenced is never deleted) |

The admin GUI switches to the new certificate at once: with *Check the device's certificate* on, acme's next requests are checked against it (a certificate of a public CA passes; for a private CA set *CA certificate*). The groups not listed in the profile default to `none`.

## Check it

On the CLI:

```text
show system global | grep admin-server-cert
show vpn ssl settings | grep servercert
show firewall ssl-ssh-profile <profile> | grep server-cert
    set server-cert "acme-www.example.com-20261112-a1b2c3"
show firewall vip <vip> | grep ssl-certificate
# the certificate itself (the command may differ between versions):
get vpn certificate local details acme-www.example.com-20261112-a1b2c3
```

The token from acme's machine:

```sh
curl -sS -H "Authorization: Bearer $TOKEN" "https://fw.example.local/api/v2/monitor/system/status"
```

Debug the REST API on the FortiGate (shows each request and why it was refused):

```text
diagnose debug application httpsd -1
diagnose debug enable
# ... run the deployment in acme ...
diagnose debug disable
diagnose debug reset
```

## Common errors

| Answer | Meaning | Fix |
|---|---|---|
| `401` | no valid token, or the request came from outside the trusted hosts | check the token (generate a new one), add acme's address to `trusthost`; behind NAT the FortiGate sees the NAT address |
| `403` | the profile lacks the permission | add the group from step 1 (certificates: `vpngrp`; admin GUI: `sysgrp cfg`; VIPs: `fwgrp`; profiles: `utmgrp`); global import needs `scope global` |
| `404` | no such profile / VIP / VDOM | check the names (case matters) and the VDOM |
| `424` (Failed Dependency) | invalid value: e.g. a certificate name not in this VDOM, or the wrong shape of `server-cert` / `ssl-certificate` | import in *global* scope (or the right VDOM); choose the module version of the FortiOS the box runs |
| `429` | rate limit, after too many bad tokens | wait, fix the token |
| `500` with `"error": <negative number>` | FortiOS refused the change (e.g. the certificate already exists on CA import - acme ignores that) | read the detail in acme's job and the `httpsd` debug |
| *the module version ... is for FortiOS ...* | the box runs another FortiOS than this version of the target is for | choose the version named in the message (or *any version*) |

*Uncertain*: whether a REST change needs a save when `cfg-save` is set to `manual` (it is saved by default); the exact negative FortiOS error numbers differ between versions.

Sources: Fortinet's Ansible collection `fortinet.fortios` 2.6.0 (attribute version ranges 6.0.0 - 8.0.0), FortiOS 7.4.8 CMDB schemas, the FortiOS 6.0.4 REST API reference (token, trusted hosts, access groups, HTTP codes) and the FortiOS 7.6 monitor API.
