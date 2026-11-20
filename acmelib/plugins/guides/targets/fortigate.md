# FortiGate (any version - detects it) - setup for acme

acme talks to the FortiGate through the **FortiOS REST API** with an **API token** (`Authorization: Bearer <token>`, HTTPS only). It imports the certificate under a dated name (`acme-<name>-<date>-<serial>`, at most 35 characters) through `POST /api/v2/monitor/vpn-certificate/local/import` (PKCS#12 with a one-time password, or certificate + key PEM), imports the intermediates as CA certificates, points the services you ticked at it and deletes older acme certificates beyond *keep*.

## Which FortiOS this guide is for

Module version **"any version (detects it)"** (`''`): FortiOS **6.0 to 8.0** - acme reads the version from `monitor/system/status` and picks the shapes itself; when the version cannot be read, or a shape is refused, it tries the other shape.

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
| SSL/SSH inspection profiles | `config firewall ssl-ssh-profile` / `set server-cert` | by version: a name up to 6.4, a list of certificates from 7.0 |
| Virtual IPs | `config firewall vip` / `set ssl-certificate` | by version: a name up to 7.4.1, a list of certificates from 7.4.2 |

**SSL VPN on FortiOS 7.6.3 and later**: SSL VPN tunnel mode is gone (its settings such as `tunnel-ip-pools` and `dtls-tunnel` end at 7.6.2 in the API data) and web mode is called *Agentless VPN*; `vpn ssl settings servercert` stays and is what acme sets. On FortiOS 7.6 some smaller models do not have SSL VPN at all (from Fortinet's release notes, *not* in the API documents - check yours); there leave *SSL VPN certificate* off.

acme does not create profiles, VIPs or the SSL VPN itself, and does not switch an inspection profile to `server-cert-mode replace` - set that up once yourself.

## Replace an existing certificate in place (keep its uses)

When a certificate on the FortiGate is already bound to policies, VIPs, ZTNA rules, user authentication or anything else, and you only want to swap it, choose in the deployment **Certificate on the FortiGate: Replace an existing certificate in place** and then **The certificate on the FortiGate**:

- **Find on the device** lists the local certificates of the FortiGate over REST with the token: name, CN, expiry, issuer, global/vdom, how many objects use it and the start of its SHA-256. FortiOS 7.6 lists them without their PEM, so acme takes these facts from `GET /api/v2/monitor/system/available-certificates` (else it reads each one). The one with the names of acme's certificate is marked ★ and chosen. Fortinet factory certificates (`Fortinet_*`, source *factory*) are left out - they are not replaced.
- **Type it yourself…** always works too, e.g. when the token may not list the certificates; the line under the list says why the listing failed. The name is case-sensitive.

**How to replace: the REST API** (the default) needs nothing but the API token - its admin profile needs only **VPN (`vpngrp`) read-write** for this (more only for what you tick or list below). No SSH. Each deployment:

```
1  GET  /api/v2/cmdb/vpn.certificate/local/<name>?with_meta=1      the certificate (not there / factory: stop)
2  GET  /api/v2/monitor/system/available-certificates?scope=…&with_ca=1   fingerprints of all certificates
3  POST /api/v2/monitor/vpn-certificate/ca/import                  each intermediate not there yet, BEFORE the swap
4  DELETE /api/v2/cmdb/vpn.certificate/local/<copy>                only acme's own unused copy of the new certificate
5  PUT  /api/v2/cmdb/vpn.certificate/local/<name>                  the new certificate (the leaf) and its key,
                                                                   encrypted with a one-time password
6  GET  /api/v2/cmdb/vpn.certificate/local/<name>?with_meta=1      its fingerprint must be the new one
```

A usual renewal is steps 1, 2, 5 and 6 - one write. When FortiOS refuses the PUT it changes nothing, and acme says why: *duplicated* (the same certificate under another name), *Invalid private key, password may be required* (the key or its password), *not a valid/matched certificate* (a key of another certificate). The service using the certificate (admin GUI, VIP...) serves the new one by itself within a few seconds.

**The least rights for replacing over the REST API** - a profile with nothing but VPN (`vpngrp`) read-write, and a REST API admin with it (the full profile under *Set up the FortiGate* is for the default mode and the uses you tick):

```text
config system accprofile
    edit "acme-replace"
        set comments "acme: replace certificates in place over the REST API"
        set scope global
        set secfabgrp none
        set ftviewgrp none
        set authgrp none
        set sysgrp none
        set netgrp none
        set loggrp none
        set fwgrp none
        set vpngrp read-write
        set utmgrp none
        set wifi none
    next
end
config system api-user
    edit "acme"
        set comments "acme certificate manager"
        set accprofile "acme-replace"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.0.2.10 255.255.255.255
            next
        end
    next
end
execute api-user generate-key acme
```

- `192.0.2.10` is an example - use acme's address (every node of a cluster: `edit 2`...; IPv6: `ipv6-trusthost`). The token is shown **once**.
- `set scope global`: the chosen certificate is usually in the *global* range (FortiGate without VDOMs too). A certificate only in a VDOM: `scope vdom` is enough, `set vdom` that VDOM.
- In the deployment leave *Admin GUI certificate*, *SSL VPN certificate*, inspection profiles and virtual IPs off or empty - the replaced certificate keeps all its uses by itself, and each of them would need more rights (`sysgrp`, `fwgrp`, `utmgrp`).
- *Checked on a FortiGate 40F, 7.4.13 with VDOMs (2026-11-20)*: `vpngrp` read-write alone is enough for every call acme makes - `monitor/system/status`, `monitor/system/available-certificates`, `cmdb/system/global` (read: the VDOM mode and the management VDOM), `cmdb/system/vdom`, the certificate PUT and the range switch, `monitor/vpn-certificate/local/import` and `ca/import` - with the profile of `scope global` and of `scope vdom` alike. Note: even a profile of `scope vdom` may import global CA certificates and make certificates of the global range.

**How to replace: SSH** is the other way (FortiOS CLI, as in acme 1.0.129). Fill in the target's **SSH user (replace over SSH)** and its key or **SSH password** - an administrator who may change VPN certificates (`vpngrp` read-write; a certificate in the *global* range needs `scope global`, e.g. a *super_admin*). The key card's *Try reaching it* runs `get system status`. These SSH fields are optional and used only by this way; without them a deployment set to SSH fails before anything changes. Over SSH acme runs:

```
get system status                                (version, VDOMs)
[config global | config vdom / edit <vdom>]      only with VDOMs on: by the certificate's range
config vpn certificate local
  edit "<name>"
    set password "<one-time password>"           the key is sent encrypted with it
    set private-key "<PEM>"
    set certificate "<the certificate, PEM>"
  abort                                          first: FortiOS checks the lines, nothing is saved
```

and, when FortiOS took every line, the same lines ending with `next` / `end` (saved), then reads the certificate back.

Both ways:

- **Only the leaf is stored**: FortiOS keeps the certificate itself and drops the rest of a chain; it sends the chain from its CA certificates. That is why acme imports the intermediates as CA certificates (over the REST API *before* the swap, so the whole chain is served from the first second).
- **A FortiGate with an EVAL/trial licence takes no RSA authority over 512 bits** (measured on a FortiGate-VM, 7.6.8: a CA of RSA 1024, 2048 or 4096 bits refused with error `-324`, RSA 512 and EC P-384 taken). An RSA certificate (e.g. Let's Encrypt's R10–R14) cannot be put there with its chain: acme stops before anything changes, names the intermediate's key, and does not try again by itself. On an EVAL FortiGate use an **EC (ECDSA)** certificate - its intermediate (Let's Encrypt E5–E9, P-384) is taken. acme sees an EVAL FortiGate-VM by its serial (`FGVMEV...`) and refuses such a chain before it imports anything. On a licensed FortiGate RSA and EC both work.
- **A name the FortiGate does not have** (1.0.136): *When it is not there* = **create it under this name** (the default) imports the certificate under exactly that name - as the default mode imports a new one - with its intermediates; every deployment after it replaces it in place. *stop* keeps the behaviour of 1.0.135: the deployment stops and changes nothing. FortiOS takes names of 35 characters at most.
- **Key format** (1.0.136, advanced): how the private key goes to FortiOS. *automatic* (the default) gives it PKCS#8 encrypted with a one-time password first; when FortiOS says the key is not right (*not a valid/matched*, *Invalid private key*) it tries the next format - PKCS#8 encrypted with PBKDF2 2048, traditional (PKCS#1 / SEC1) encrypted, PKCS#8, traditional. Every refusal changes nothing; the job says which one FortiOS took, and that one may then be chosen. Over SSH the same formats are tried, each first ended with `abort`.
- **SSH sign-in on a real FortiGate** (1.0.136): an admin of a profile has the prompt `$`, the answer follows the prompt on its line with no terminal, and the console may page (`--More--`) - acme reads the answer of `get system status` through all of it and goes through the pager.
- **FortiOS 7.4 with VDOMs** (measured on a FortiGate 40F, 7.4.13, 2026-11-20): a local certificate of a VDOM's range (`range vdom`) refuses every PUT of another certificate with "Input is not a valid/matched certificate", whatever the key. acme then puts it in through the global range and back - `PUT {key, certificate, "range": "global"}`, then `PUT {"range": "vdom"}` - with the same token (VPN read-write); its name and everything bound to it stay. On that way FortiOS checks nothing, so acme checks before (the key is the certificate's and opens with its password - else nothing is sent; no copy of the certificate in the VDOM or global) and after (the fingerprint and the key size, read by `available-certificates?scope=vdom`). The range not set back: the new certificate works, yet of the global range - said, not tried again. A 200 with the old certificate still there (FortiOS dropped the write): the deployment stops and says to check the certificate. With a VDOM acme always reads the fingerprints with `scope=vdom` (`scope=global` leaves the VDOM's certificates out).
- **FortiOS 7.4, a VDOM other than the management VDOM** (measured on 7.4.13, 2026-11-20): there a certificate of the global range is only an image of the management VDOM's - switching a certificate of that VDOM's range to global **empties it** (no fingerprint, key size 0; the range cannot be set back, `-145`). acme therefore takes the way through the global range **only in the management VDOM** (`management-vdom` of `system global`, which `vpngrp` reads). Elsewhere a certificate of the VDOM's range cannot be replaced over the REST API: acme stops before it writes anything - or, with the target's SSH sign-in filled in, replaces it in the FortiOS CLI. A certificate of the global range is always written in the management VDOM. Every write is read back (`available-certificates?scope=vdom`): an empty entry is said as broken and not tried again. A copy of the global range is deleted in every VDOM (deleted in one, it stays elsewhere as an empty entry). A name created by "When it is not there" is read back too (FortiOS cuts a name over 35 characters without a word); made in another VDOM than the management one, acme warns that the next deployments need SSH.
- **Duplicates**: FortiOS never keeps the same local certificate under two names ("This local certificate is duplicated") - e.g. the same certificate imported earlier by a deployment in the default mode (this was the error of acme 1.0.128). acme looks for the new certificate by its fingerprint first: already at the chosen name - nothing to do ("already in place"); a copy acme made for this certificate (`acme-<name>-…`) - deleted first, and said; FortiOS refuses to delete a copy that is used ("currently being used", `-23`) - then the deployment stops with the target untouched: point the copy's uses at the chosen name and deploy again; a copy acme did not make - the deployment stops before anything changes and names it. The chosen certificate is never deleted, and this mode never imports the certificate under a new name.
- The **name stays**, so everything bound to it keeps using it and nothing is re-pointed. Admin GUI, SSL VPN, profiles and VIPs are set only when you tick or list them - then to that same name. The key type may change (RSA → ECDSA): the certificate's uses keep it.
- A name not on the FortiGate fails before anything is changed; *What happens* shows each step (for the REST API: the reads, the CA certificates to import, the copies to delete, the swap and the check).
- If FortiOS refuses, the deployment fails with its error lines (never a PEM or a key) and the old certificate stays as it was. acme's cleanup of its own older `acme-...` certificates never takes the replaced one.
- **The name cannot be edited - that is normal**: FortiOS never lets you rename a local certificate; its GUI *Edit* of any imported certificate shows only *Comments*. Replace in place is how a certificate keeps its name.
- The same in every module version (FortiOS 6.0 - 8.0). Measured on FortiOS 7.6.8; on 7.4 and older the same API is expected (not yet verified on a device).

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
- Tighter firewall rights (FortiOS 7.0.1 and later have `others` in `fwgrp-permission`). *Uncertain*: the documents do not say which part VIPs belong to (*Address* or *Other*), so this gives both:

```text
config system accprofile
    edit "acme-cert"
        set fwgrp custom
        config fwgrp-permission
            set policy none
            set address read-write
            set service none
            set schedule none
            set others read-write
        end
    next
end
```

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
| Module version | **any version (detects it)** |
| Address / HTTPS port | the FortiGate's management address and admin HTTPS port (`admin-sport`, default 443) |
| API token | the key from `execute api-user generate-key` |
| VDOM | `root`, your VDOM, or empty without VDOMs |
| Check the device's certificate | on; off only while the FortiGate still has its self-signed `Fortinet_GUI_Server` |
| Admin GUI / SSL VPN certificate (deploy) | tick what should use the certificate |
| SSL/SSH inspection profiles, Virtual IPs (deploy) | one name a line, e.g. `inbound-replace`, `vip-www` |
| SSH user (replace over SSH), its key or SSH password | only when *How to replace* is SSH: an admin with `vpngrp` read-write (global range: `scope global`); empty otherwise - replace over the REST API needs the token only |
| Previous versions to keep (advanced) | older acme certificates to keep (one still referenced is never deleted) |

The admin GUI switches to the new certificate at once: with *Check the device's certificate* on, acme's next requests are checked against it (a certificate of a public CA passes; for a private CA set *CA certificate*). The groups not listed in the profile default to `none`.

## Check it

On the CLI:

```text
show system global | grep admin-server-cert
show vpn ssl settings | grep servercert
show firewall ssl-ssh-profile <profile> | grep server-cert
# 6.x: set server-cert "acme-www.example.com-20261112-a1b2c3"
# 7.0+: set server-cert "Fortinet_SSL_ECDSA256" "acme-www.example.com-20261112-a1b2c3"
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
| `500` with `"error": <negative number>` | FortiOS refused the change (`-328` on a CA import: it is there already - measured, acme notes it once) | read the detail in acme's job and the `httpsd` debug |
| *FortiOS refused to replace … in place* | FortiOS did not take the new certificate or key of the local certificate (the reason and its error lines are said); nothing changed, the old one stayed | *duplicated*: another local certificate is the same one - see Duplicates above; *Invalid private key*: the key or its password; *not a valid/matched*: a key of another certificate |
| *replace in place over SSH ("How to replace": SSH) and the target has no SSH sign-in* | the SSH way needs the target's SSH user and key or password | fill them in (an admin with `vpngrp` read-write), or choose the REST API |
| *… an earlier import of acme that is in use - FortiOS refused to delete it (-23 …)* | a copy of the new certificate is in use, FortiOS does not delete it | point its uses at the chosen name, deploy again |
| *the FortiGate has this very certificate already as …* | an identical local certificate under another name, used or not acme's - FortiOS refuses a duplicate | point its uses at the chosen name, delete it, deploy again |
| *there is no local certificate …* | no certificate of that name on the FortiGate (in that VDOM) | **Find on the device**, or the exact name (case matters) |
| *the module version ... is for FortiOS ...* | the box runs another FortiOS than this version of the target is for | choose the version named in the message (or *any version*) |
| SSL VPN refused on 7.6 | the model has no SSL VPN / Agentless VPN | leave *SSL VPN certificate* off |

*Uncertain*: whether a REST change needs a save when `cfg-save` is set to `manual` (it is saved by default); the exact negative FortiOS error numbers differ between versions.

Sources: Fortinet's Ansible collection `fortinet.fortios` 2.6.0 (attribute version ranges 6.0.0 - 8.0.0), FortiOS 7.4.8 CMDB schemas, the FortiOS 6.0.4 REST API reference (token, trusted hosts, access groups, HTTP codes) and the FortiOS 7.6 monitor API.
