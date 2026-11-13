# HPE Aruba Networking ArubaOS 8 (Mobility Conductor, kontrolery) - nastavení pro acme

acme se ke kontroleru přihlásí přes **SSH** a posílá řádky CLI do shellové relace SSH. AOS 8 bere soubor certifikátu jen ze své **flash** a nic - ani REST API, ani CLI - neumožňuje acme soubor předat přímo. acme proto soubor uloží na **pomocný server** (linuxový server, na který dosáhne přes SSH) a kontroler si ho stáhne příkazem `copy tftp:` (nebo `copy scp:`). Pak:

1. `crypto pki-import pfx ServerCert acme-<název>-<datum>-<sériové číslo> <soubor> <jednorázové heslo>` - certifikát s klíčem (PKCS#12); certifikační autority řetězce jako `IntermediateCA` / `TrustedCA` s názvem `acme-ca-<id>`, každou jednou;
2. `web-server profile` → `switch-cert` (správa přes WebUI) a volitelně `captive-portal-cert`;
3. `write memory`;
4. soubor hned smaže z pomocného serveru i z flash; starší `ServerCert` od acme nad *ponechat*, na které nic neodkazuje, odstraní (`no crypto-local pki ServerCert`).

> **Neověřeno**: dokumentaci HPE techdocs se při psaní modulu nepodařilo otevřít celou. Příkazy pocházejí ze stránek AOS 8 CLI Bank (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`) tak, jak byly vidět ve výňatcích, a z průvodce dodavatele. Na zařízení neověřeno: řádky poslané do shellové relace bez terminálu, odpověď na heslo, na které se ptá `copy scp:`, `delete filename`, rozložení výpisu `show crypto-local pki`, zda kontroler servíruje řetězec z PKCS#12. Vyzkoušejte to nejdřív na jednom kontroleru a sledujte kroky úlohy.

## Pro které AOS 8 je tento návod

Verze modulu **„jakákoli verze (zjistí ji)“** - jediná: **ArubaOS 8.6 - 8.13** (Mobility Conductor, Mobility Controller i samostatný kontroler). Žádný přečtený dokument neukazuje v těchto příkazech rozdíl mezi 8.10, 8.12 a 8.13. acme přečte `show version`: **AOS 6** (jiné příkazy `web-server`) a **AOS 10** (konfiguruje se z Central - použijte cíl `aruba_central`) odmítne dřív, než cokoli změní; novější než 8.13 jen upozorní.

## Co acme na kontroleru mění

| Volba v acme | CLI AOS 8 | Dopad |
|---|---|---|
| (vždy) | `copy tftp: <server> <soubor> flash: <soubor>`, `crypto pki-import pfx ServerCert <název> <soubor> <heslo>`, `delete filename <soubor>` | nový serverový certifikát; soubor pak z flash zmizí |
| Importovat řetězec | `crypto pki-import pem IntermediateCA` / `TrustedCA acme-ca-<id> <soubor>` | každá CA jednou, ponechá se pro další certifikáty |
| Konfigurační uzel (Conductor) | `cd <uzel>`, `crypto-local pki ServerCert <název> <soubor>` | certifikát je známý v daném uzlu hierarchie |
| Certifikát pro správu přes WebUI | `web-server profile`, `no switch-cert`, `switch-cert <název>` | **webový server se restartuje**: relace WebUI a REST API na 4343 se na okamžik přeruší |
| Certifikát captive portálu | `web-server profile`, `no captive-portal-cert`, `captive-portal-cert <název>` | nová přihlášení hostů dostanou nový certifikát |
| Uložit konfiguraci | `write memory` | bez něj změna po reloadu zmizí |
| Kolik předchozích verzí ponechat | `no crypto-local pki ServerCert <starý>` | jen vlastní certifikáty acme a jen s počtem odkazů 0 |

## Nastavení kontroleru

### 1. Účet pro acme

Import certifikátů a změna `web-server profile` vyžadují roli správy **root** (AOS 8 nemá roli jen pro certifikáty). Na Conductoru nebo kontroleru:

```text
configure terminal
mgmt-user acme root
write memory
```

`mgmt-user` se dvakrát zeptá na heslo. Lépe: účet z TACACS+ / RADIUS (ClearPass) s rolí root, s auditem a se správou dostupnou jen z adresy acme. V acme se přihlašujte **heslem** (přihlášení klíčem SSH na AOS 8 nebylo pro tento modul ověřeno). Pokud účet skončí v neprivilegovaném režimu (`>`), vyplňte *Heslo pro enable*.

### 2. Pomocný server

Libovolný linuxový server, na který kontroler dosáhne. S **TFTP** (výchozí):

```sh
sudo apt-get install tftpd-hpa
sudo useradd -m -s /bin/bash acme
sudo passwd acme
sudo chown acme /srv/tftp
sudo systemctl enable --now tftpd-hpa
```

- kontroler musí dosáhnout na UDP **69** serveru (a odpovědi); acme na jeho port SSH;
- soubor (s privátním klíčem zašifrovaným jednorázovým heslem) tam leží jen po dobu kopírování a TFTP server ho může číst; acme ho hned potom smaže.

Se **SCP** (`copy scp:`) se kontroler na pomocný server přihlašuje sám, heslem pomocného uživatele (u pomocného serveru nastavte *Přihlásit se přes* na heslo); soubor zůstane jen uživateli (práva 600). Složka může být libovolná, kam uživatel smí zapisovat, např. `/home/acme/stage`.

### 3. Mobility Conductor

Na Conductoru se certifikát WebUI nastavuje ve `web-server profile` uzlu, kde se používá (`/md`, `/md/branch`, `/mm/mynode`). Vyplňte *Konfigurační uzel*: acme tam provede `cd <uzel>` a `crypto-local pki ServerCert <název> <soubor>`. Samostatný kontroler nepotřebuje ani jedno. V clusteru si člen může ponechat vlastní nastavení (přepsání na úrovni zařízení) - zkontrolujte `show web-server profile` na každém.

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **jakákoli verze (zjistí ji)** |
| Adresa | adresa správy kontroleru, např. `mcr01.example.com` |
| SSH port / Uživatel | `22` / `acme` |
| Přihlásit se přes, Heslo | heslo (krok 1) |
| Klíč serveru (rozšířené) | řádek known_hosts kontroleru; prázdné s *Věřit prvnímu viděnému klíči serveru* vezme první |
| Heslo pro enable (rozšířené) | jen když účet skončí v režimu `>` |
| Konfigurační uzel (rozšířené) | Conductor: `/md/branch` nebo `/mm/mynode`; samostatný kontroler: prázdné |
| Port WebUI (rozšířené) | `4343` |
| Šifrování PKCS#12 (rozšířené) | 3DES s MAC SHA-1 |
| Kontroler si soubor stáhne přes | TFTP z pomocného serveru (nebo SCP) |
| Pomocný server | adresa, na kterou se acme přihlásí přes SSH, např. `tftp.example.com` |
| Jeho adresa pro kontroler | adresa, na které ho kontroler najde (prázdné: stejná) |
| Složka na pomocném serveru | `/srv/tftp` (kořen TFTP) |
| SSH port / Uživatel / Přihlásit se přes (pomocný server) | `22` / `acme` / klíč acme nebo heslo (SCP: heslo) |
| Certifikát pro správu přes WebUI (switch-cert) (nasazení) | zapnuto |
| Certifikát captive portálu (captive-portal-cert) (nasazení) | podle potřeby; *Jméno captive portálu* pro test |
| Importovat řetězec (IntermediateCA, TrustedCA) (nasazení) | zapnuto |
| Uložit konfiguraci (write memory) (nasazení) | zapnuto |
| Kolik předchozích verzí ponechat (rozšířené) | `1` |

## Ověření

Na kontroleru:

```text
show crypto-local pki ServerCert
show crypto-local pki IntermediateCA
show web-server profile
```

Ze stroje acme:

```sh
openssl s_client -connect mcr01.example.com:4343 -servername mcr01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Časté problémy

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| *zařízení řeklo „Error: ... not found in path /md/...“* | certifikát v tom uzlu není známý | vyplňte *Konfigurační uzel*, nebo importujte v uzlu, kde je profil |
| *copying ... to flash: ...* | kontroler soubor nestáhl | UDP 69 k pomocnému serveru, kořen TFTP = *Složka na pomocném serveru*; SCP: heslo |
| *Expecting string of length 1 to 31* | příliš dlouhý název | názvy acme se do 31 znaků vejdou; vlastní název (*object_name*) musí také |
| *... is not there after the import* | import nic nehlásil, ale certifikát nepřevzal | `show crypto-local pki ServerCert`; zkuste *Šifrování PKCS#12* 3DES |
| *runs ArubaOS 10 ...* | gateway s AOS 10 | cíl `aruba_central` |
| test toho, co se servíruje, hned po nasazení selže | webový server se restartuje | acme sám počká |
| WebUI ukazuje jen serverový certifikát bez řetězce | řetězec se neservíruje | nechte zapnuté *Importovat řetězec* |

Zdroje: AOS 8 CLI Bank (`crypto pki-import`, `crypto-local pki`, `web-server profile`, `copy`), AOS 8 User Guide (Managing Certificates, Configuring Certificate Authentication for WebUI Access, SCP server support), reference REST API AOS 8 (bez nahrání certifikátu), průvodce dodavatele `aos8-aos10-central.md`.
