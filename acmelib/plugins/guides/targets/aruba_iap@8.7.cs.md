# HPE Aruba Networking Instant AP (AOS 8) (Instant 8.7 - 8.13) - nastavení pro acme

acme se přes **SSH** přihlásí k **virtuálnímu kontroleru** clusteru Instant AP s **Instant 8.7 - 8.13** a posílá řádky CLI do shellové relace SSH. Na **pomocný server** (linuxový server, na který dosáhne přes SSH, sdílený přes TFTP nebo jinou URL) uloží **PKCS#12** (klíč, certifikát, řetězec; jednorázové heslo), nechá ho AP naimportovat a přiřadí ho - od Instant 8.7.0.0 platí certifikát až po přiřazení k aplikaci:

```text
crypto pki-import format pfx cert-type ServerCert url tftp://<pomocný server>/acme-<sériové číslo>.pfx certname acme-<název>-<datum>-<sériové číslo> psk <jednorázové heslo>
configure terminal
wlan cert-assignment-profile
pki-cert-assign application ui cert-type ServerCert certname acme-<název>-<datum>-<sériové číslo>
pki-cert-assign application captive-portal cert-type ServerCert certname acme-<název>-<datum>-<sériové číslo>
exit
exit
commit apply
```

`captive-portal` jen když je zvolený. Pak musí `show cert assignment` uvádět nový certifikát (jinak upozornění). Soubor se z pomocného serveru hned po importu smaže.

Verze modulu **Instant 8.7 - 8.13**: AP, které ohlásí jinou verzi (`show version`), acme odmítne dřív, než cokoli změní - před 8.7 zvolte *Instant 8.3 - 8.6*.

> **Neověřeno**: klíčová slova `crypto pki-import` (format / cert-type / url / certname / psk) a URL schémata, ze kterých AP stahuje, jsou z Instant CLI Bank, jak byla vidět ve výňatcích (příklad používá FTP a obsahuje překlep) - příkaz je v rozšířeném poli *Příkaz importu (Instant 8.7 a novější)* (`{format}` `{url}` `{name}` `{psk}`) a URL v poli *URL, odkud si ho AP stáhne*, takže obojí lze opravit; `commit apply` po přiřazení; na zařízení neověřeno. Starší certifikáty acme neodstraňuje (`crypto pki-remove` ručně).

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
| Verze modulu | **Instant 8.7 - 8.13** |
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
