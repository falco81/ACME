# Dell PowerStore - nastavení pro acme

acme nahraje certifikát **i s klíčem** na **cluster PowerStore** jako certifikát správy
clusteru (služba `Management_HTTP`, scope `External` - PowerStore Manager a REST API na portu
443) přes REST API:

```text
GET  /api/rest/login_session                       basic auth -> DELL-EMC-TOKEN + auth_cookie
GET  /api/rest/software_installed?select=release_version&is_cluster=eq.true
POST /api/rest/x509_certificate   {"type":"Server","service":"Management_HTTP","scope":"External",
                                   "certificate":"<server + mezilehlé, jeden řetězec>",
                                   "private_key":"<klíč PEM>","is_current":true}
GET  /api/rest/x509_certificate/<id>?select=id,is_current,is_valid
POST /api/rest/logout
```

Certifikát se použije hned; nic se nerestartuje a I/O úložiště to neovlivní (otevřená okna
PowerStore Manageru je třeba otevřít znovu).

> **Nejdřív vyzkoušejte.** Dell dokumentuje certifikát správy **jen z CSR, které si vytvoří
> sám cluster** (Settings → Security → Signed Cluster Certificate → Generate CSR, nebo
> `POST /api/rest/x509_certificate/csr`, a pak import podepsaného řetězce). Import klíče
> vytvořeného jinde je volání z vlastního SDK Dellu (PyPowerStore `create_certificate`:
> `certificate`, `private_key`, `is_current`), pro `Management_HTTP` nezdokumentované. Pokud ho
> vaše PowerStoreOS odmítne, acme to oznámí a **nic se nezmění** - takový cluster certifikát
> z acme převzít nedokáže a zůstane mu vlastní (nebo ručně vyměněný z jeho CSR).

## Pro které PowerStoreOS

**PowerStoreOS 3.0 - 4.4** (jeden modul: stejná volání). Verze 2.x brala certifikát správy
jen na samostatném blokovém appliance bez replikace - acme ji odmítne dřív, než cokoli změní.
Novější verze pokračuje s varováním.

## Účet (nejmenší oprávnění)

Certifikát clusteru je bezpečnostní nastavení: role **Security Administrator** (role id `5`),
případně Administrator. Operator jen čte.

```sh
pstcli -d powerstore.example.local -u admin -p '<heslo-admina>' local_user create -name acme -password '<silne-heslo>' -role_id 5
```

Nebo v PowerStore Manageru: **Settings → Users → Users → Add**, role *Security Administrator*.
Přes REST (token admina z `login_session`):

```sh
curl -k -u admin:'<heslo-admina>' -X POST https://powerstore.example.local/api/rest/local_user \
  -H "DELL-EMC-TOKEN: <token>" -H 'Content-Type: application/json' \
  -d '{"name":"acme","password":"<silne-heslo>","role_id":"5"}'
```

## Jaký musí certifikát být

- Klíč RSA **2048 nebo 4096**; řetězec server → mezilehlé → kořenový v jednom řetězci (acme
  posílá serverový certifikát a mezilehlé, které má; samotný certifikát bez CA neprojde).
- Platnost ještě **nejméně 30 dní** (kratší PowerStore odmítne).
- Jména: DNS jméno clusteru a **IP adresy clusteru a ICM** (veřejná CA privátní IP
  nepodepíše - Dell doporučuje interní CA).
- Při replikaci: po změně spusťte *Verify and Update* vzdáleného systému.

## Vyplňte v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | adresa správy clusteru, `443` |
| Uživatel / Heslo | účet `acme` |
| Ověřovat certifikát zařízení | při prvním nasazení přes self-signed certifikát vypnuto (nebo vyplňte *Certifikát CA*), potom zapnuto |
| Zkontrolovat, co se servíruje | prázdné: acme ověří adresu cíle |

## Ověření

```sh
openssl s_client -connect powerstore.example.local:443 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
pstcli -d powerstore.example.local -u acme -p '<heslo>' x509_certificate show
```

## Návrat k self-signed certifikátu

```sh
pstcli -d powerstore.example.local -u admin -p '<heslo-admina>' x509_certificate reset_certificates -service Management_HTTP -scope External
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `does not take a key made elsewhere` | Tato PowerStoreOS importuje certifikát správy jen z vlastního CSR - automatizovat nejde; vyměňte ho ručně. |
| `0xE09010010013` (ověřte řetězec certifikátů) | Neúplný řetězec nebo špatné pořadí; certifikát platný méně než 30 dní. |
| `401` / `403` | Špatné heslo, nebo účet není Security Administrator / Administrator. |
| `runs PowerStoreOS 2.x` | Aktualizujte na 3.0 nebo novější. |
| Po změně selhává replikace | *Verify and Update* vzdáleného systému (KB 000211671). |
