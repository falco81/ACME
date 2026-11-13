# HPE Aruba Networking Instant AP (AOS 8) (Instant 8.3 - 8.6) - nastavení pro acme

acme se přes **SSH** přihlásí k **virtuálnímu kontroleru** clusteru Instant AP s **Instant 8.3 - 8.6** a posílá řádky CLI do shellové relace SSH. Na **pomocný server** (linuxový server, na který dosáhne přes SSH a jehož složku sdílí TFTP server) uloží **PEM** - privátní klíč zašifrovaný jednorázovým heslem, certifikát a řetězec - a nechá ho AP načíst:

```text
copy tftp <pomocný server> acme-<sériové číslo>.pem uiserver cert <jednorázové heslo> format pem
copy tftp <pomocný server> acme-<sériové číslo>.pem cpserver cert <jednorázové heslo> format pem
```

První je certifikát WebUI (4343), druhý captive portálu (jen když je zvolený). Certifikát platí hned - tyto verze nemají profil přiřazení certifikátů a `commit apply` není potřeba. Soubor se z pomocného serveru hned potom smaže.

Verze modulu **Instant 8.3 - 8.6**: AP, které ohlásí jinou verzi (`show version`), acme odmítne dřív, než cokoli změní - Instant 8.7 a novější potřebují import a přiřazení verze *Instant 8.7 - 8.13*.

> **Neověřeno**: slova `copy tftp ... uiserver|cpserver cert <heslo> format pem` jsou z Instant CLI Bank / příručky 8.3, jak byly vidět ve výňatcích (starší Instant používal `ui` / `cp`); používá se jen TFTP (pole *URL, odkud si ho AP stáhne* tato verze nepoužívá); na zařízení neověřeno. Starší certifikáty acme neodstraňuje.

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
| Verze modulu | **Instant 8.3 - 8.6** |
| Adresa | adresa virtuálního kontroleru, např. `iap.example.com` |
| SSH port / Uživatel | `22` / `admin` |
| Přihlásit se přes, Heslo | heslo |
| Klíč serveru (rozšířené) | řádek known_hosts AP; prázdné s *Věřit prvnímu viděnému klíči serveru* vezme první |
| Port WebUI (rozšířené) | `4343` |
| Pomocný server | adresa, na kterou se acme přihlásí přes SSH |
| Jeho adresa pro AP | adresa, na které ho AP najde (prázdné: stejná) |
| Složka na pomocném serveru | `/srv/tftp` (kořen TFTP) |
| SSH port / Uživatel / Přihlásit se přes (pomocný server) | `22` / `acme` / klíč acme nebo heslo |
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
