# Cisco Secure Firewall Management Center (FMC 7.7 - 10.0) - nastavení pro acme

Tato verze cíle dělá totéž co verze bez čísla - certifikát jako nový objekt **Internal Certificate**, pravidla *Decrypt - Known Key* v uvedených dešifrovacích politikách přepnutá na něj, nasazení - a od FMC **7.7** navíc dá certifikát na **zařízení** (Devices → Certificates: trustpoint pro **RA VPN**, SAML, S2S VPN):

```text
GET  /api/fmc_platform/v1/info/serverversion                          verze FMC (7.7 a novější)
GET  /api/fmc_config/v1/domain/<d>/object/certenrollments             objekt enrollmentu podle jména
POST /api/fmc_config/v1/domain/<d>/object/certenrollments             poprvé
PUT  /api/fmc_config/v1/domain/<d>/object/certenrollments/<id>        při každé obnově: nový PKCS#12
     {"type": "CertEnrollment", "name", "enrollmentType": "PKCS12",
      "pkcs12Content": {"base64Certificate", "passPhrase"},
      "validationUsage": {"ipsecClient": true, "sslServer": true}}
GET  /api/fmc_config/v1/domain/<d>/devices/devicerecords              zařízení podle jména
GET  /api/fmc_config/v1/domain/<d>/devices/certificates?filter=deviceId:<id>&expanded=true
POST /api/fmc_config/v1/domain/<d>/devices/operational/managecertificates
     {"action": "ENROLL" (poprvé na zařízení) | "RE_ENROLL",
      "deviceCertificates": [{"deviceId", "certificates": [{"certificate": {"id": <enrollment>}}]}]}
```

Objekt enrollmentu si drží **jedno jméno**, a tak ho drží i trustpoint na zařízeních: profily připojení RA VPN (Access Interfaces → *Certificate Enrollment*), které na něj odkazují, se měnit nemusí.

## Pro které FMC

Verze modulu **„FMC 7.7 - 10.0“**: FMC **7.7.x a 10.0**. FMC 7.4 a 7.6 neumějí přes API zapsat certifikát na zařízení (`managecertificates` a `devices/certificates` jsou od 7.7; jejich `certenrollments` bere jen PKCS12 a MANUAL CA-only) - tam použijte verzi bez čísla, která obslouží jen Internal Certificates. Na jiném FMC tato verze odmítne dřív, než cokoli změní.

| Verze modulu | FMC | Internal Certificate + dešifrovací pravidla | Certifikát zařízení (trustpoint) |
|---|---|---|---|
| (bez čísla) | 7.4 - 10.0 | ano | ne |
| FMC 7.7 - 10.0 | 7.7 - 10.0 | ano (nebo vypnuto) | ano |

## Co se na zařízeních stane

- **Enrollment proběhne hned, bez nasazení** (Devices → Certificates ukáže trustpoint jako *Available*). Použití trustpointu v politice nasazení potřebuje - jednou, když ho poprvé uvedete v RA VPN.
- RA VPN: nová spojení klientů dostanou nový certifikát, běžící tunely zůstanou. Secure Client musí CA věřit (jinak „Untrusted server“). S2S IKEv2: při dalším vyjednání.
- `managecertificates` běží jako úloha: acme o ni požádá a na její konec nečeká - zkontrolujte *Devices → Certificates*.

## Nastavení FMC

1. **REST API**: *Administration → Configuration → REST API Preferences → Enable REST API* (10.0; v 7.7 *System (ozubené kolo) → Configuration*). V HA jen na aktivním FMC.
2. **Role pro acme** (*Administration → Users → User Roles*): zkopírujte *Network Admin*, ponechte práva na objekty PKI (Object Manager), **Devices → Certificates** a pokud acme nasazuje, **Deploy Configuration to Devices** - *nejisté*: přesné názvy těchto práv ověřte v *User Roles*.
3. **Uživatel jen pro API** (*Administration → Users → Create User*), např. `api-acme`, s touto rolí, v doméně zařízení. Nepoužívejte ho ve webovém rozhraní: přihlášení stejným účtem tam API odhlásí.
4. Poznamenejte si jména zařízení (*Devices → Device Management*) a zvolte jméno objektu enrollmentu, např. `RAVPN-acme`. Po prvním nasazení tento trustpoint jednou vyberte v profilu připojení RA VPN a nasaďte.

Přihlášení si vyzkoušejte:

```sh
curl -sk -i -X POST -u 'api-acme:<heslo>' https://fmc.example.com/api/fmc_platform/v1/auth/generatetoken
```

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **FMC 7.7 - 10.0** |
| Adresa / Port HTTPS | FMC, např. `fmc.example.com` / `443` |
| Uživatel / Heslo | účet jen pro API z kroku 3 |
| UUID domény (rozšířené) | prázdné: doména, kterou vrátí přihlášení |
| Objekt Cert Enrollment (PKCS12) (nasazení) | např. `RAVPN-acme`; prázdné: žádný certifikát zařízení |
| Zapsat na tato zařízení (nasazení) | po řádcích jména zařízení, např. `ftd-1` |
| Také Internal Certificate (nasazení) | zapnuto: jako verze bez čísla (dešifrovací pravidla); vypnuto: jen certifikát zařízení |
| Dešifrovací politika, Další dešifrovací politiky, Nasadit na zařízení, Jen tato zařízení (nasazení) | jako ve verzi bez čísla |
| Kolik předchozích verzí ponechat (rozšířené) | pro Internal Certificates, výchozí `1` |

## Ověření

Na FMC: *Devices → Certificates* (trustpoint, *Available*, datum vypršení); přes API:

```sh
curl -sk -H "X-auth-access-token: $TOKEN" "https://fmc.example.com/api/fmc_config/v1/domain/$DOMAIN/devices/certificates?filter=deviceId:<device-uuid>&expanded=true"
```

Na zařízení (`system support diagnostic-cli`):

```text
show crypto ca certificates RAVPN-acme
show crypto ca trustpoints
```

Zvenku:

```sh
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| *this device runs FMC 7.6...* | FMC starší než 7.7 | verze cíle bez čísla |
| *the FMC has no device ...* | jméno není v Device Management | přesné jméno zařízení |
| *the Cert Enrollment ... is of the type SCEP* | jméno patří jinému druhu enrollmentu | jiné jméno (PKCS12, které patří acme) |
| `400` / `422` u enrollmentu | PKCS#12 odmítnut (nad 24 kB, řetězec, typ klíče) | velikost a klíč certifikátu (RSA 2048+ / ECDSA) |
| zařízení má po RE_ENROLL dál starý certifikát | viz *Nejisté* | *Devices → Certificates → Refresh*, nebo ho tam jednou znovu zapište |

*Nejisté* (průvodce je označuje): pole `certenrollments` jsou z Terraform provideru Cisca (`fmc_certificate_enrollment`, `fmc_device_certificate`), ne z reference API; zda `RE_ENROLL` objektu PKCS12 převezme PKCS#12 vložený přes `PUT`, nebylo na zařízení ověřeno; `serverversion` je obvyklé volání FMC, průvodce ho necituje.

Zdroje: FMC REST API Quick Start Guide 10.0 (Objects in the REST API, About the FMC REST API - Certificates / Manage Certificates od 7.7), FMC Device Configuration Guide 10.0 (Certificates), Terraform provider Cisca `CiscoDevNet/fmc`.
