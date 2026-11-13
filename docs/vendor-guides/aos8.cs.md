# HPE Aruba Networking AOS 8 (Mobility Conductor, kontrolery, Instant AP) - certifikáty

**acme už cíle má**: `aruba_aos8` (Mobility Conductor, Mobility Controller, AOS 8.6 - 8.13) a `aruba_iap` (Instant AP; verze *Instant 8.3 - 8.6* a *Instant 8.7 - 8.13*, nebo *libovolná verze (zjistí ji)*). Jak je nastavit, říkají jejich návody (tlačítko *Návod k nastavení* v acme; `acmelib/plugins/guides/targets/aruba_aos8.cs.md`, `aruba_iap*.cs.md`). Protože REST API AOS 8 nedokumentuje nahrání certifikátu, oba cíle pracují přes SSH CLI a **pomocný server**: acme zapíše soubor na linuxový server přes SSH a zařízení si ho stáhne (`copy tftp:` / `copy scp:` na kontroleru, URL nebo `copy tftp` na Instant).

**Neověřeno**: CLI je teď převzaté ze stránek **CLI Bank** pro AOS 8 / Instant (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`, `wlan cert-assignment-profile`), ty však byly čteny jen ve výňatcích z vyhledávání (techdocs se nepodařilo otevřít celé) a na zařízení se nic nespouštělo. Vyzkoušejte nejdřív jedno zařízení. Instant AP a gatewaye AOS 10 spravované z Central: použijte cíl `aruba_central`.

Dále následuje, co cíle dělají, ručně - pro přehled nebo tam, kde acme použít nejde.

## Postup (AOS 8.x, CLI na Conductoru nebo kontroleru - syntaxe podle CLI Bank, *na zařízení neověřeno*)

```text
(host) [mynode] # copy scp: <server> <user> /certs/mcr01.pfx flash: mcr01.pfx
(host) [mynode] # crypto pki-import pfx ServerCert mcr01-2026 mcr01.pfx <heslo-pfx>
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

`crypto-local pki ServerCert` je potřeba v konfiguračním uzlu Conductoru (nejdřív `cd /md/...`); CLI Bank ukazuje `no switch-cert` / `no captive-portal-cert` před nastavením nového. Změna `switch-cert` restartuje webový server (WebUI i REST na 4343 se přeruší). Serverový certifikát 802.1X lze nastavit přes REST API (zdokumentovaný objekt `dot1x_auth_profile`):

```sh
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/dot1x_auth_profile?config_path=/md&UIDARUBA=<token>" \
  -d '{"profile-name": "corp-dot1x", "server_cert": {"server-cert-name": "radius-2026"}}'
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/write_memory?config_path=/md&UIDARUBA=<token>" -d '{}'
```

## Instant AP (ručně)

Instant 8.7 a novější (certifikát platí až po přiřazení; klíčová slova jsou *neověřená*):

```text
crypto pki-import format pfx cert-type ServerCert url tftp://192.0.2.10/iap.pfx certname iap-2026 psk <heslo-pfx>
configure terminal
wlan cert-assignment-profile
pki-cert-assign application ui cert-type ServerCert certname iap-2026
exit
exit
commit apply
show cert assignment
```

Instant 8.3 - 8.6: `copy tftp 192.0.2.10 iap.pem uiserver cert <heslo> format pem` (WebUI), `... cpserver ...` (captive portál).

## Ověření

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Zdroje: REST API AOS 8 (login, configuration object, write_memory, `dot1x_auth_profile`); CLI Bank pro AOS 8 a Instant (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`, `wlan cert-assignment-profile`) čtené ve výňatcích z vyhledávání; průvodce dodavatele.
