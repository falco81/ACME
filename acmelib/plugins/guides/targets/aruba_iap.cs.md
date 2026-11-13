# HPE Aruba Networking Instant AP (AOS 8) - nastavení pro acme

acme se přes **SSH** přihlásí k **virtuálnímu kontroleru** clusteru Instant AP (certifikáty se importují jen na řídicím AP a rozejdou se na všechny členy) a posílá řádky CLI do shellové relace SSH. AP bere certifikát jen ze serveru, odkud si ho sám stáhne, proto acme soubor uloží na **pomocný server** (linuxový server, na který dosáhne přes SSH, sdílený přes TFTP nebo jinou URL), nechá AP soubor stáhnout a hned ho smaže. Co se AP řekne, záleží na jeho verzi:

| Verze modulu | Instant | Co acme posílá |
|---|---|---|
| libovolná verze (zjistí ji) | 8.3 - 8.13 | podle `show version`: od 8.7 postup pro 8.7, dříve postup pro 8.3; neznámá: 8.7 (s upozorněním) |
| Instant 8.3 - 8.6 | 8.3 - 8.6 | `copy tftp <server> <soubor> uiserver cert <heslo> format pem` (WebUI), `... cpserver ...` (captive portál) - PEM s klíčem zašifrovaným jednorázovým heslem, certifikátem a řetězcem |
| Instant 8.7 - 8.13 | 8.7 - 8.13 | `crypto pki-import format pfx cert-type ServerCert url <url> certname <název> psk <heslo>`, pak `wlan cert-assignment-profile` / `pki-cert-assign application ui` (a `captive-portal`) `cert-type ServerCert certname <název>`, `commit apply` |

Od Instant 8.7.0.0 platí certifikát až po přiřazení k aplikaci - proto se verze liší. AP s AOS 10 (konfigurované z Central) acme odmítne: použijte cíl `aruba_central`. Cluster Instant spravovaný z Central: také `aruba_central` - změnu na virtuálním kontroleru Central přepíše.

> **Neověřeno**: dokumentaci HPE techdocs se při psaní modulu nepodařilo otevřít celou; příkazy jsou ze stránek Instant CLI Bank (`crypto pki-import`, `wlan cert-assignment-profile`, `copy`) a z uživatelské příručky Instant 8.x, jak byly vidět ve výňatcích. Na zařízení neověřeno: klíčová slova `crypto pki-import` (příklad v CLI Bank obsahuje překlep) a které URL schémata AP umí stáhnout (příklad je FTP) - proto je příkaz v rozšířeném poli *Příkaz importu (Instant 8.7 a novější)* a URL v poli *URL, odkud si ho AP stáhne*; `commit apply` po přiřazení; řádky poslané do shellové relace bez terminálu. Starší certifikáty acme z AP neodstraňuje (`crypto pki-remove` ručně).

## Nastavení AP

### 1. Účet pro acme

Instant má jednoho místního správce (`admin`) s plnými právy, nebo správce z RADIUS / TACACS+ s rolí *admin*. acme potřebuje plná práva: import i `commit apply` jsou konfigurace.

```text
configure terminal
mgmt-user admin <silné-heslo>
exit
commit apply
```

V acme se přihlašujte **heslem**. SSH musí být zapnuté (Instant: *System > Admin > SSH*, nebo výchozí stav).

### 2. Pomocný server

Libovolný linuxový server, na který AP dosáhne. S **TFTP**:

```sh
sudo apt-get install tftpd-hpa
sudo useradd -m -s /bin/bash acme
sudo passwd acme
sudo chown acme /srv/tftp
sudo systemctl enable --now tftpd-hpa
```

AP musí dosáhnout na UDP **69** serveru. Soubor (privátní klíč zašifrovaný jednorázovým heslem) tam leží jen po dobu stahování. Pro FTP nastavte *URL, odkud si ho AP stáhne* např. na `ftp://uzivatel:heslo@{addr}/{dir}/{file}` a *Složku na pomocném serveru* na složku uživatele FTP.

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **libovolná verze (zjistí ji)** (nebo ta pro váš Instant) |
| Adresa | adresa virtuálního kontroleru, např. `iap.example.com` |
| SSH port / Uživatel | `22` / `admin` |
| Přihlásit se přes, Heslo | heslo |
| Klíč serveru (rozšířené) | řádek known_hosts AP; prázdné s *Věřit prvnímu viděnému klíči serveru* vezme první |
| Port WebUI (rozšířené) | `4343` |
| Příkaz importu (Instant 8.7 a novější) (rozšířené) | nechte, pokud váš Instant nemá jinou syntaxi |
| Pomocný server | adresa, na kterou se acme přihlásí přes SSH |
| Jeho adresa pro AP | adresa, na které ho AP najde (prázdné: stejná) |
| Složka na pomocném serveru | `/srv/tftp` (kořen TFTP) |
| SSH port / Uživatel / Přihlásit se přes (pomocný server) | `22` / `acme` / klíč acme nebo heslo |
| URL, odkud si ho AP stáhne (rozšířené) | `tftp://{addr}/{file}` |
| Certifikát WebUI (nasazení) | zapnuto |
| Certifikát captive portálu (nasazení) | podle potřeby; *Jméno captive portálu* pro test |

## Ověření

Na AP:

```text
show cert assignment
show version
```

Ze stroje acme:

```sh
openssl s_client -connect iap.example.com:4343 -servername iap.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Časté problémy

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| *zařízení řeklo „% Invalid input ...“* při importu | tento Instant má jinou syntaxi | opravte *Příkaz importu*; nebo zvolte *Instant 8.3 - 8.6*, je-li starší než 8.7 |
| *Validate certificate date failed* / *Cert file check fail* | hodiny AP (známá chyba Instant 8.3 porovnává místní čas s GMT) | NTP a časové pásmo na AP |
| *show cert assignment does not name ...* | přiřazení se neuplatnilo | `show cert assignment`, `commit apply` ručně |
| *runs AOS 10 ...* | AP s AOS 10 | cíl `aruba_central` |
| *verze modulu ... je pro Instant ...* | AP má jiný Instant | zvolte verzi uvedenou ve zprávě |

Zdroje: Instant CLI Bank (`crypto pki-import`, `crypto pki-remove`, `wlan cert-assignment-profile`, `copy`), uživatelská příručka Instant 8.x (Authentication Certificates, Uploading Certificates), průvodce dodavatele `aos8-aos10-central.md`.
