# NetApp ONTAP (ONTAP 9.6 - 9.9) - nastavení pro acme

acme mluví s management LIF clusteru přes **ONTAP REST API** (`https://<cluster-mgmt>/api/...`, přihlášení HTTP basic). S každým novým certifikátem:

1. nainstaluje ho jako certifikát typu **server** – `POST /api/security/certificates` s `name` (`acme-<jméno>-<datum>-<sériové číslo>`), `type: server`, `public_certificate`, `private_key` a všemi mezilehlými certifikáty v `intermediate_certificates` (ONTAP certifikát typu server s chybějícím mezilehlým odmítne); v rozsahu clusteru, nebo v datovém SVM (`svm.name`);
2. když ONTAP odpoví `202`, počká na úlohu (`GET /api/cluster/jobs/<uuid>`);
3. nastaví ho webovým službám (System Manager, REST API) – kam, závisí na verzi ONTAP, viz níže; ONTAP pak **restartuje webové služby** (otevřené relace System Manageru a REST se odpojí, NFS/SMB/iSCSI se to netýká);
4. smaže starší certifikáty acme téhož jména nad počet *Kolik předchozích verzí ponechat* – až po přepnutí, nikdy ten používaný.

## Pro které ONTAP je tento návod

Verze modulu **ONTAP 9.6 - 9.9** (`9.6`): ONTAP 9.6 – 9.9, které ještě nemají endpointy `/web`. Certifikát se přiřazuje přes pole `certificate` clusteru nebo SVM (NetApp ho od 9.10 označuje za zastaralé – „Support for this field will be removed in a future release“ –, ale stále funguje):

```text
PATCH /api/cluster               {"certificate": {"uuid": "<uuid>"}}   cluster
PATCH /api/svm/svms/<svm-uuid>   {"certificate": {"uuid": "<uuid>"}}   datové SVM
```

acme nejdřív přečte verzi (`GET /api/cluster?fields=version`): cluster s 9.10.1 nebo novějším odmítne dřív, než cokoli změní (zvolte *ONTAP 9.10.1 - 9.19*). REST API `POST /api/security/certificates` je k dispozici od 9.6. Tyto verze už NetApp nepodporuje – návod výrobce popisuje 9.16 – 9.19; naplánujte upgrade.

## Co potřebujete

- HTTPS správu (ve výchozím stavu zapnutá; HTTP je vypnuté) dostupnou z acme na portu 443.
- Funkční NTP na clusteru – certifikát s `notBefore` v budoucnosti se nepoužije.
- Certifikát s FQDN clusteru (a podle KB NetApp i FQDN/IP uzlů) v SAN. RSA nebo EC; ve FIPS režimu aspoň 2048 bitů a bez MD5/SHA-1.

## Účet s nejmenšími právy

Certifikátové příkazy jsou pro administrátory clusteru a SVM na úrovni oprávnění admin. Tradiční role jen s tím, co acme potřebuje (admin SVM = jméno clusteru, zde `cluster1`):

```text
security login role create -vserver cluster1 -role cert_admin -cmddirname "security certificate" -access all
security login role create -vserver cluster1 -role cert_admin -cmddirname "security ssl" -access all
security login role create -vserver cluster1 -role cert_admin -cmddirname "vserver services web" -access readonly
security login role create -vserver cluster1 -role cert_admin -cmddirname "DEFAULT" -access none
security login create -vserver cluster1 -user-or-group-name svc_cert -application http -authentication-method password -role cert_admin
```

Nebo REST role:

```text
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/security/certificates" -access all
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/cluster/web" -access read_modify
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/svm/svms" -access read_modify
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/cluster" -access readonly
security login create -vserver cluster1 -user-or-group-name svc_cert -application http -authentication-method password -role cert_rest
```

- Aplikace `http` pokrývá REST API (i System Manager); `ssh` acme nepotřebuje.
- *Nejisté*: NetApp nemá příklad, který by dokládal, že tato minimální sada REST rolí na přiřazení certifikátu stačí (`/api/cluster/web`, `/api/svm/svms/*/web`). Když volání odpoví `403`, dejte účtu předdefinovanou roli `admin` na admin SVM.
- Na ONTAP 9.6 – 9.9 se přiřazuje přes `PATCH /api/cluster` – dejte této cestě `read_modify` místo `readonly`.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **ONTAP 9.6 - 9.9** |
| Adresa / Port HTTPS | management LIF clusteru (FQDN), `443` |
| Uživatel / Heslo | `svc_cert` a jeho heslo |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má cluster svůj self-signed certifikát (nebo jeho CA vložte do *Certifikát CA*) |
| SVM (nasazení) | prázdné pro webové služby samotného clusteru; jméno datového SVM pro jeho webové služby |
| Čekat na úlohu (s) (pokročilé) | jak dlouho čekat na úlohu po odpovědi `202` (`120`) |
| Kolik předchozích verzí ponechat (pokročilé) | starší certifikáty acme, které zůstanou (`1`) |
| Zkontrolovat, co se servíruje | u SVM jeho management LIF, např. `svm1.example.com:443` (cluster se zkontroluje sám) |

Po přiřazení ONTAP restartuje webové služby: odpověď na toto volání může být useknutá – acme pak přečte `/api/cluster` a podívá se, co je přiřazeno. Se zapnutým *Ověřovat certifikát zařízení* se další požadavky acme ověřují proti novému certifikátu (u privátní CA vyplňte *Certifikát CA*).

## Ověření

```sh
openssl s_client -connect cluster1.example.com:443 -servername cluster1.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName
curl -u svc_cert "https://cluster1.example.com/api/cluster?fields=certificate"
curl -u svc_cert "https://cluster1.example.com/api/security/certificates?type=server&fields=name,common_name,serial_number,expiry_time,svm"
```

V CLI:

```text
security ssl show -vserver cluster1
security certificate show -vserver cluster1 -type server -fields common-name,serial,ca,expiration
```

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| `Failed to read the X509 from BIO` | formát, který ONTAP neumí přečíst (PKCS#7) | acme posílá PEM – zkontrolujte certifikát v acme |
| instalace selže na řetězci | chybí mezilehlý certifikát | řetězec vydavatele musí být v acme úplný |
| `403` na `/api/cluster` | REST role nemá tuto cestu | dejte jí `read_modify` nebo použijte roli `admin` |
| *the module version ... is for ONTAP ...* | cluster běží na jiné verzi ONTAP | zvolte verzi uvedenou ve zprávě (nebo *jakoukoli verzi*) |
| System Manager vás odhlásí | webové služby se po přiřazení restartují | očekávané; přihlaste se znovu |
| starý certifikát se nesmaže | je stále někde přiřazený | acme ho ponechá a řekne to; smažte ho později ručně |

Zdroje: NetApp ONTAP REST API reference (`security/certificates`, `cluster/web`, `svm/svms/{uuid}/web`, `PATCH /cluster`), ONTAP CLI reference (`security certificate install`, `security ssl modify`, `security login role create`, `security login rest-role create`).
