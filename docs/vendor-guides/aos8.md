# HPE Aruba Networking AOS 8 (Mobility Conductor, controllers, Instant AP) - certificates by hand (no acme target)

acme has **no target** for AOS 8 controllers: the AOS 8 REST API (`/v1/api/login`, `/v1/configuration/object`) documents no call that uploads a certificate file, and the object for `web-server profile` (`switch-cert`, `captive-portal-cert`) is not in the API reference. The import is CLI or WebUI only - and the CLI syntax could not be checked against Aruba's documents (techdocs answered 403). Instant APs managed by Central: use the `aruba_central` target. A controller managed by Central (AOS 10 gateway): `aruba_central` too.

## The steps (AOS 8.12 / 8.13, CLI on the Conductor or controller - *uncertain syntax*)

```text
(host) [mynode] # copy scp: <server> <user> /certs/mcr01.pfx flash: mcr01.pfx
(host) [mynode] # crypto pki-import pfx ServerCert mcr01-2026 mcr01.pfx <pfx-password>
(host) [mynode] # crypto pki-import pem IntermediateCA Example-Issuing issuing.pem
(host) [mynode] # configure terminal
(host) [mynode] (config) # web-server profile
(host) [mynode] (Web Server Configuration) # switch-cert mcr01-2026
(host) [mynode] (Web Server Configuration) # captive-portal-cert guest-2026
(host) [mynode] (config) # write memory
(host) [mynode] # show crypto-local pki ServerCert
```

Changing `switch-cert` restarts the web server (WebUI and REST on 4343 cut). The 802.1X server certificate can be set over the REST API (documented object `dot1x_auth_profile`):

```sh
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/dot1x_auth_profile?config_path=/md&UIDARUBA=<token>" \
  -d '{"profile-name": "corp-dot1x", "server_cert": {"server-cert-name": "radius-2026"}}'
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/write_memory?config_path=/md&UIDARUBA=<token>" -d '{}'
```

## Check it

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Sources: AOS 8 REST API (login, configuration object, write_memory, `dot1x_auth_profile`); the CLI from the guide's general knowledge.
