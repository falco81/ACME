# HPE Aruba Networking AOS 8 (Mobility Conductor, controllers, Instant AP) - certificates

**acme has targets now**: `aruba_aos8` (Mobility Conductor, Mobility Controller, AOS 8.6 - 8.13) and `aruba_iap` (Instant AP; versions *Instant 8.3 - 8.6* and *Instant 8.7 - 8.13*, or *any version (detects it)*). Their setup guides (button *Setup guide* in acme; `acmelib/plugins/guides/targets/aruba_aos8.md`, `aruba_iap*.md`) say how to set them up. Because the AOS 8 REST API documents no certificate upload, both work over SSH CLI and a **staging server**: acme writes the file to a Linux server over SSH and the device fetches it (`copy tftp:` / `copy scp:` on a controller, a URL or `copy tftp` on Instant).

**Unverified**: the CLI is now taken from the AOS 8 / Instant **CLI Bank** pages (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`, `wlan cert-assignment-profile`), but those were read through search excerpts only (techdocs could not be opened in full) and nothing was run on a device. Try one device first. Instant APs and AOS 10 gateways managed by Central: use the `aruba_central` target.

What the targets do by hand, for reference or when acme cannot be used, follows.

## The steps (AOS 8.x, CLI on the Conductor or controller - CLI Bank syntax, *unverified on a device*)

```text
(host) [mynode] # copy scp: <server> <user> /certs/mcr01.pfx flash: mcr01.pfx
(host) [mynode] # crypto pki-import pfx ServerCert mcr01-2026 mcr01.pfx <pfx-password>
(host) [mynode] # crypto pki-import pem IntermediateCA Example-Issuing issuing.pem
(host) [mynode] # configure terminal
(host) [mynode] (config) # crypto-local pki ServerCert mcr01-2026 mcr01.pfx
(host) [mynode] (config) # web-server profile
(host) [mynode] (Web Server Configuration) # no switch-cert
(host) [mynode] (Web Server Configuration) # switch-cert mcr01-2026
(host) [mynode] (Web Server Configuration) # no captive-portal-cert
(host) [mynode] (Web Server Configuration) # captive-portal-cert guest-2026
(host) [mynode] (config) # write memory
(host) [mynode] # show crypto-local pki ServerCert
```

`crypto-local pki ServerCert` is needed on a Conductor's config node (`cd /md/...` first); the CLI Bank shows `no switch-cert` / `no captive-portal-cert` before a new one. Changing `switch-cert` restarts the web server (WebUI and REST on 4343 cut). The 802.1X server certificate can be set over the REST API (documented object `dot1x_auth_profile`):

```sh
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/dot1x_auth_profile?config_path=/md&UIDARUBA=<token>" \
  -d '{"profile-name": "corp-dot1x", "server_cert": {"server-cert-name": "radius-2026"}}'
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/write_memory?config_path=/md&UIDARUBA=<token>" -d '{}'
```

## Instant AP (by hand)

Instant 8.7 and later (a certificate works only when assigned; the keyword form is *unverified*):

```text
crypto pki-import format pfx cert-type ServerCert url tftp://192.0.2.10/iap.pfx certname iap-2026 psk <pfx-password>
configure terminal
wlan cert-assignment-profile
pki-cert-assign application ui cert-type ServerCert certname iap-2026
exit
exit
commit apply
show cert assignment
```

Instant 8.3 - 8.6: `copy tftp 192.0.2.10 iap.pem uiserver cert <password> format pem` (WebUI), `... cpserver ...` (captive portal).

## Check it

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Sources: AOS 8 REST API (login, configuration object, write_memory, `dot1x_auth_profile`); AOS 8 and Instant CLI Bank (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`, `wlan cert-assignment-profile`) read through search excerpts; the vendor guide.
