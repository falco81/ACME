# Infoblox NIOS - nastavení pro acme

acme mluví s **WAPI** na **Grid Masteru** (HTTPS 443, HTTP basic) a certifikát s řetězcem a klíčem - jeden nešifrovaný PEM - nahraje jako **HTTPS certifikát** (`certificate_usage` `ADMIN`: Grid Manager, WAPI, DoT/DoH členu) nebo certifikát **Captive Portal** každého člena Gridu, kterého uvedete, přes `fileop` WAPI:

```text
POST /wapi/v2.11/fileop?_function=uploadinit         {"filename": "acme-....pem"}  -> {"token", "url"}
POST <url>                                           multipart: file = certifikát + řetězec + klíč
POST /wapi/v2.11/fileop?_function=uploadcertificate  {"certificate_usage": "ADMIN", "member": "<fqdn>", "token": "<token>"}
```

NIOS pak certifikát člena nahradí (jako *Replace HTTPS Certificate* v GUI, jen bez dotazu), restartuje jeho webový server a **odhlásí administrátory**. Nic se nemaže. Adresa `url` pro nahrání může Grid Master jmenovat adresou, na kterou acme nedosáhne (NAT): acme ji pošle na adresu cíle, stejně jako `ibx-sdk` od Infoblox-PS.

## Pro které verze

NIOS **8.6, 9.0 a 9.1** - stejná volání (stránky HTTPS certifikátu v 9.1 odpovídají 9.0). WAPI má verze nezávislé na NIOS a starší verze ponechává; acme výchozí používá **2.11** (je v 8.6 - 9.1; NIOS 9.0.6 má 2.13.6). Co váš Grid nabízí:

```sh
curl -s -u svc-cert "https://gm.example.local/wapi/v1.0/?_schema" | python3 -m json.tool | grep -A20 supported_versions
```

Od NIOS 9.0.6 se odmítají certifikáty podepsané SHA-1 a od 9.0.2 se certifikáty CA kontrolují podle RFC 5280 - certifikát z ACME nebo veřejné CA projde.

## 1. Účet pro acme

Dokumentace neuvádí, které oprávnění s omezeným přístupem smí nahrát HTTPS certifikát člena; Infoblox doporučuje **superuser skupinu, které je povoleno jen API**:

1. *Administration → Administrators → Groups → Add (+)*: Name `cert-automation`, zaškrtnout **Superusers**, **Allowed Interfaces**: jen **API (WAPI/PAPI only)** - GUI a CLI odškrtnout. *Save & Close*.
2. *Administration → Administrators → Admins → Add*: lokální admin `svc-cert` s dlouhým heslem, Admin Group `cert-automation`.

Totéž přes WAPI (jako superuser):

```sh
curl -s -u admin -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/admingroup" \
  -d '{"name":"cert-automation","superuser":true,"access_method":["API"],"comment":"acme certificates"}'
curl -s -u admin -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/adminuser" \
  -d '{"name":"svc-cert","password":"<dlouhé heslo>","admin_groups":["cert-automation"]}'
```

*Nejisté*: může stačit skupina s omezeným přístupem a rolemi **Grid Admin** a **PKI Admin** (nebo *All Members* pro čtení i zápis) - vyzkoušejte; 401/403 u `uploadcertificate` znamená, že ne.

## 2. Co potřebuje Grid

- WAPI běží na Grid Masteru - není co zapínat. Volání `fileop` jdou na **Grid Master** i pro jiného člena (určuje ho `member`).
- Každý uvedený člen musí v Gridu existovat pod svým jménem hostitele (*Grid → Grid Manager → Members*).
- Jména v certifikátu musí pokrýt to, co používají lidé i acme: FQDN Grid Masteru (u HA páru i jméno jeho VIP).
- Správný čas (NTP) v Gridu.

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | Grid Master, `443` |
| Uživatel / Heslo | `svc-cert` a jeho heslo |
| Verze WAPI (pokročilé) | `2.11` (nebo nejnovější, kterou váš Grid uvádí, např. `2.13.7`) |
| Ověřovat certifikát zařízení | zapnuto (s *Certifikátem CA*, když je certifikát Gridu od privátní CA); dokud má výchozí certifikát `www.infoblox.com`, pro první nasazení vypnuto |
| Členové Gridu (nasazení) | jedno jméno hostitele na řádek, jak je zná Grid; **Grid Master naposled** - jeho WAPI se s novým certifikátem restartuje |
| Použít jako (nasazení) | *HTTPS certifikát* (ADMIN) nebo *certifikát Captive Portal* |
| Zkontrolovat, co se servíruje (nasazení) | acme sám otestuje každého člena na portu 443 (HTTPS certifikát); další přidejte sem, např. jméno VIP |

Uveďte i **Grid Master Candidate**: po povýšení by jinak servíroval svůj vlastní (výchozí) certifikát. Po nahrání certifikátu samotného Grid Masteru acme počká, až se jeho WAPI vrátí (ptá se znovu každých 10 s po dobu minuty).

## Ověřte to

```sh
openssl s_client -connect gm.example.local:443 -servername gm.example.local -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Certifikát člena přes WAPI:

```sh
curl -s -u svc-cert -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/fileop?_function=downloadcertificate" \
  -d '{"certificate_usage":"ADMIN","member":"gm.example.local"}'
# pak GET na vrácenou url a POST fileop?_function=downloadcomplete {"token": "..."}
```

V GUI: *Grid → Grid Manager → Members → člen → Certificates → HTTPS Cert → Download Certificate*.

**Návrat zpět**, když GUI nejde otevřít: na konzoli člena vyberte dřívější certifikát:

```text
Infoblox > set apache_https_cert
```

## Časté problémy

| Odpověď | Význam | Řešení |
|---|---|---|
| `401` | špatný uživatel nebo heslo, nebo skupina nemá povolené API | *Allowed Interfaces: API* |
| `403` / *permission* | skupina s omezeným přístupem bez oprávnění | superuser skupina s povoleným jen API (krok 1) |
| `400` u `uploadcertificate` | člen, kterého Grid nezná, certifikát SHA-1, klíč nepatří k certifikátu | jméno hostitele člena jako v *Members*; certifikát |
| *cannot be reached* po nahrání na Grid Master | restartuje se jeho webový server | acme minutu čeká; Grid Master uveďte naposled |
| prohlížeč ukazuje starý certifikát | člen není uveden (kandidát, druhý uzel HA) | uveďte ho |

*Neověřeno* (z návodu výrobce): nejmenší oprávnění pro ne-superusery, jméno části multipart `file` (používají ho ukázky Infobloxu i ibx-sdk), co se stane s oběma uzly HA páru a zda se restartuje jen webový server.
