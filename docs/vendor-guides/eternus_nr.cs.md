# Fujitsu ETERNUS NR (NR1000, ONTAP) - nastavení pro acme

Systémy ETERNUS NR1000 běží na **NetApp ONTAP** - acme na ně nasazuje cílem **NetApp ONTAP
(REST API)** (`netapp_ontap`): nainstaluje certifikát s klíčem a mezilehlými certifikáty
(`POST /api/security/certificates`, typ `server`) a nasměruje na něj webové služby clusteru
(nebo SVM) (`PATCH /api/cluster/web` nebo `security ssl modify`), potom smaže starší, které tam
acme dalo. Nic z toho není specifické pro Fujitsu: příručky NR od Fujitsu odkazují na
dokumentaci ONTAP.

**Které verze:** ONTAP 9.10.1 a novější (správa certifikátů v System Manageru; ověřeno podle
ONTAP 9.19.1); pro ONTAP 9.6 - 9.9 zvolte verzi modulu *ONTAP 9.6 - 9.9*. Na kterém vydání ONTAP
vaše NR1000 běží, zjistíte příkazem `version` v CLI (nebo u Fujitsu / Fsas).

## Co potřebujete

- Z acme na LIF správy clusteru: **TCP 443**; zapnuté webové služby `rest` a `ontapi`
  (`vserver services web show`), firewallová politika `mgmt` povoluje `https`.
- Účet clusteru pro HTTP (REST) s rolí omezenou na cesty certifikátů:

  ```text
  cluster1::> security login rest-role create -role cert_rest -api /api/security/certificates -access all
  cluster1::> security login rest-role create -role cert_rest -api /api/cluster/web -access all
  cluster1::> security login create -user-or-group-name svc_cert -application http -authentication-method password -role cert_rest
  ```

  (Ověřte `security login rest-role` na svém vydání ONTAP; funguje i vestavěná role `admin`.)
- **Všechny mezilehlé certifikáty** - ONTAP odmítne serverový certifikát s neúplným řetězcem;
  acme je posílá.

## Vyplnění v acme

Vytvořte cíl **NetApp ONTAP (REST API)**:

| Pole v acme | Co tam patří |
|---|---|
| Adresa | LIF správy clusteru, např. `nr01.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | `svc_cert` |
| SVM (nasazení) | Prázdné pro vlastní certifikát clusteru; jméno SVM pro dané SVM |
| Zkontrolovat, co se servíruje | Prázdné: adresa správy clusteru |

Zbytek popisuje vlastní návod toho cíle (*Návod k nastavení* v jeho formuláři).

## Ověření

```sh
openssl s_client -connect nr01.example.local:443 -servername nr01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

```text
cluster1::> security certificate show -vserver cluster1 -type server
cluster1::> security ssl show
```
