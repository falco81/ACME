# HPE Aruba Networking AOS 8 (Mobility Conductor, kontrolery, Instant AP) - certifikáty ručně (bez cíle v acme)

acme pro kontrolery AOS 8 **nemá cíl**: REST API AOS 8 (`/v1/api/login`, `/v1/configuration/object`) nedokumentuje žádné volání, které by nahrálo soubor certifikátu, a objekt pro `web-server profile` (`switch-cert`, `captive-portal-cert`) v referenci API není. Import jde jen přes CLI nebo WebUI - a syntaxi CLI se nepodařilo ověřit v dokumentaci Aruby (techdocs vracely 403). Instant AP spravované z Central: použijte cíl `aruba_central`. Kontroler spravovaný z Central (gateway AOS 10): také `aruba_central`.

## Postup (AOS 8.12 / 8.13, CLI na Conductoru nebo kontroleru - *neověřená syntaxe*)

```text
(host) [mynode] # copy scp: <server> <user> /certs/mcr01.pfx flash: mcr01.pfx
(host) [mynode] # crypto pki-import pfx ServerCert mcr01-2026 mcr01.pfx <heslo-pfx>
(host) [mynode] # crypto pki-import pem IntermediateCA Example-Issuing issuing.pem
(host) [mynode] # configure terminal
(host) [mynode] (config) # web-server profile
(host) [mynode] (Web Server Configuration) # switch-cert mcr01-2026
(host) [mynode] (Web Server Configuration) # captive-portal-cert guest-2026
(host) [mynode] (config) # write memory
(host) [mynode] # show crypto-local pki ServerCert
```

Změna `switch-cert` restartuje webový server (WebUI i REST na 4343 se přeruší). Serverový certifikát 802.1X lze nastavit přes REST API (zdokumentovaný objekt `dot1x_auth_profile`):

```sh
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/dot1x_auth_profile?config_path=/md&UIDARUBA=<token>" \
  -d '{"profile-name": "corp-dot1x", "server_cert": {"server-cert-name": "radius-2026"}}'
curl -sk -b aruba-cookie -H 'Content-Type: application/json' -X POST \
  "https://mcr01.example.com:4343/v1/configuration/object/write_memory?config_path=/md&UIDARUBA=<token>" -d '{}'
```

## Ověření

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Zdroje: REST API AOS 8 (login, configuration object, write_memory, `dot1x_auth_profile`); CLI z obecné znalosti průvodce.
