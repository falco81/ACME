# HPE Aruba Networking AOS-CX switch - nastavení pro acme

acme nainstaluje certifikát s klíčem na switch přes **REST API AOS-CX** pod jménem s datem (`acme-<název>-<datum>-<sériové číslo>`, nejvýš 32 znaků), přidá každou CA řetězce jako **trust anchor profil** (`acme-ca-<id>`, jednou), nasměruje na certifikát aplikace, které uvedete (výchozí `https-server` - WebUI a REST API), uloží konfiguraci a smaže starší certifikáty acme, které žádná aplikace nepoužívá.

```text
POST   /rest/latest/login?username=...&password=...        session cookie
POST   /rest/latest/system/pki_ta_profiles                  {"name", "certificate", "revocation_check_mode": "disabled"}
PUT    /rest/latest/certificates/<name>                     {"certificate": klíč + certifikát + řetězec}
PATCH  /rest/latest/system                                  {"certificate_association": {"https-server": "<name>", ...}}
GET    /rest/latest/system?attributes=certificate_association_status
PUT    /rest/latest/fullconfigs/startup-config?from=/rest/latest/fullconfigs/running-config
DELETE /rest/latest/certificates/<starší>
POST   /rest/latest/logout
```

## Pro které AOS-CX

**AOS-CX 10.13 - 10.18** (reference REST API v10.18; `/rest/latest` existuje od 10.09). Modul má jedinou verzi.

## Co acme mění

| Volba v acme | AOS-CX | Dopad |
|---|---|---|
| (vždy) | `crypto pki ta-profile acme-ca-<id>` | CA z řetězce - bez trust anchoru vydavatele nelze koncový certifikát nainstalovat |
| (vždy) | `crypto pki certificate acme-...` | certifikát a jeho klíč |
| Použít pro (nasazení) | `crypto pki application <aplikace> certificate acme-...` | `https-server`: HTTPS server WebUI/REST ho převezme hned - otevřené relace se mohou přerušit (acme se přihlásí znovu); `syslog-client`, `radsec-client`, `captive-portal`...: při dalším TLS spojení |
| Uložit konfiguraci | `write memory` (REST: startup-config z running-config) | vydrží reload |

Ostatní položky přiřazení zůstanou, jak jsou; aplikace s neplatným certifikátem se vrátí k self-signed certifikátu switche - acme přečte `certificate_association_status` a selže, když není `as_configured`.

## Nastavení switche

```text
configure terminal
https-server vrf mgmt
https-server rest access-mode read-write
ntp server 192.0.2.123 iburst
ntp enable
user acme group administrators password plaintext <silne-heslo>
end
write memory
```

- Zápis PKI přes REST potřebuje skupinu **administrators** (skupina uživatelů s pravidly pro CLI podle dokumentace REST API neomezí - *nejisté*).
- `https-server rest access-mode read-write` je potřeba pro jakoukoli změnu přes REST.
- Čas musí sedět (NTP).
- Přihlášení REST posílá heslo v URL (tak ho AOS-CX přijímá) - acme ho posílá jen přes HTTPS a na konci se odhlásí; zařiďte, aby proxy mezi acme a switchem URL nelogovaly.

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | `sw01.example.com` / `443` |
| Uživatel / Heslo | `acme` a jeho heslo |
| Verze REST API (rozšířené) | `latest`, nebo verze, kterou switch vypíše na `/rest` (např. `v10.13`) |
| Ověřovat certifikát zařízení | zapnuto, jakmile switch servíruje certifikát vaší CA; vypnuto jen dokud má vlastní self-signed `local-cert` |
| Použít pro (nasazení) | po řádcích: `https-server`, `syslog-client`, `captive-portal`, `radsec-client`, `hsc`, `gnmi`, `est-client`, `dot1x-supplicant` |
| Uložit konfiguraci (nasazení) | zapnuto |
| Kolik předchozích verzí ponechat (rozšířené) | `1` |

## Ověření

Na switchi:

```text
show crypto pki certificate
show crypto pki application
show crypto pki ta-profile
```

Ze stroje acme:

```sh
openssl s_client -connect sw01.example.com:443 -servername sw01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| `401` při přihlášení | špatný uživatel nebo heslo, nebo příliš mnoho relací REST | účet; staré relace vyprší |
| `403` | uživatel nesmí přes REST zapisovat | skupina `administrators`; `https-server rest access-mode read-write` |
| `404` při instalaci | toto AOS-CX takto nenainstaluje certifikát pod novým jménem | *nejistý bod* - nahlaste verzi switche; jednou ho nainstalujte ručně (`crypto pki certificate <název>` / `import terminal`) |
| *... does not use ...: the switch says configured_cert_invalid* | switch certifikát nepřijal (řetězec, typ klíče) | trust anchory; RSA 2048+ nebo ECDSA P-256/384 |

*Nejisté* (průvodce je označuje): zda `PUT /certificates/<name>` přijme klíč pro jméno, ke kterému switch nevytvořil CSR (reference: certifikát „may contain a private key if it was generated outside of the switch“); zda `PATCH /system` přijme samotné `certificate_association` (acme posílá celé přiřazení); uložení přes `fullconfigs` je obvyklé volání AOS-CX, v průvodci není.

Zdroje: reference REST API AOS-CX v10.18 (`PUT /certificates/{name}`, `POST /system/pki_ta_profiles`, `GET /system` - `certificate_association`, `login`), verzování API AOS-CX.
