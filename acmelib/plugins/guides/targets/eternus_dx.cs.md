# Fujitsu ETERNUS DX / AF (certifikát Web GUI) - nastavení pro acme

acme zaregistruje **SSL certifikát ETERNUS Web GUI** na úložišti ETERNUS DX / AF - **RESTful
API (port 5665) ho sdílí**. ETERNUS CLI bere klíč a certifikát jen ze souborového serveru,
proto acme:

1. nahraje `acme-<serial>.key` a `acme-<serial>.crt` na váš **server FTPS (nebo FTP)**,
2. přihlásí se přes **SSH** do CLI pole a spustí

   ```text
   CLI> import ssl-certificate -port maintenance -server <souborový server> -user <uživatel FTP> -cert-filename acme-<serial>.crt -key-filename acme-<serial>.key
   Password :            (acme odpoví heslem souborového serveru)
   ```

3. oba soubory ze souborového serveru zase smaže (klíč tam nezůstane),
4. na přání restartuje SMI-S s novým certifikátem (`set smi-s -function disable`, potom
   `set smi-s -function enable -ssl-certificate shared-with-webgui`).

Po registraci se **HTTP/HTTPS pole na několik minut zastaví** (Web GUI a RESTful API;
přihlášení uživatelé se odpojí). **Datový přístup (FC / iSCSI / SAS) to neovlivní.**

**Které verze:** ověřeno podle příruček ETERNUS DX S6 (CLI C140-0003-06ENZ3, Web GUI
C140-0005-06ENZ3, RESTful API C140-0052-03ENZ3); ETERNUS AF na stejné řadě firmwaru. DX S5 /
AF S3 / AF S2 mají stejné příkazy, ale jen FTP - zvolte tam *Přenos souborů: FTP na DX S5 /
AF S3*. RESTful API nemá endpoint pro certifikáty, proto CLI.

**Klíče:** RSA 1024 / 2048 / 4096, PEM; PKCS#12 ne. Použijte **RSA 2048 nebo 4096**.

## Co potřebujete

- Z acme na pole: **TCP 22** (SSH na portu MNT nebo RMT, povolené v **Setup Firewall**).
- Souborový server dostupný z obou stran: acme na něj soubory nahraje, pole si je stáhne přes
  svůj LAN port MNT, RMT nebo FST. S6 používá **FTPS (explicitní)**, pasivní režim a certifikát
  serveru neověřuje.
- Uživatele na souborovém serveru jen pro tento účel (s vlastní složkou).
- Uživatele ETERNUS s politikou **Storage Management** (výchozí role, které ji mají: *Admin*,
  *Maintainer*).

## Nastavení pole

1. Vytvořte roli jen se *Status Display* (1) a *Storage Management* (10) a uživatele pro acme
   (CLI přes SSH jako administrátor):

   ```text
   CLI> create role -name CertAdmin -policy 1,10
   CLI> create user -name svc-cert -role CertAdmin -function enable
   Password:
   Confirm Password:
   CLI> show users
   ```

   *Security Setting* (13) přidejte jen tehdy, má-li účet měnit i verze TLS.
2. Volitelně - přihlášení klíčem místo hesla: příkaz CLI `import ssh-public-key` zaregistruje
   jeden veřejný klíč na účet (parametry: CLI User's Guide, kapitola „SSH/SSL Security
   Configuration“). Veřejný klíč vezměte z karty klíče u cíle.
3. Na souborovém serveru vytvořte uživatele `stage` s domovskou složkou (nebo složkou), do které
   smí zapisovat a mazat, dostupnou z acme i z LAN portu pole.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Správcovská adresa pole, např. `dx.example.local` |
| SSH port / Uživatel | `22` / `svc-cert` |
| Přihlásit se přes / SSH klíč / Heslo | Klíč z kroku 2, nebo heslo |
| LAN port pole k souborovému serveru | *MNT* (výchozí), *RMT* nebo *FST* - port, ze kterého je souborový server dostupný |
| Souborový server / Port souborového serveru | např. `ftp.example.local` / `21` |
| Přenos souborů | *FTPS, explicitní TLS* pro S6 (výchozí); *FTP na S6* pošle `-disable-ftps yes`; *FTP na DX S5 / AF S3 / AF S2* nepošle žádnou volbu FTPS (ty umí jen FTP) |
| Uživatel souborového serveru / Heslo souborového serveru | `stage` a jeho heslo (CLI se na něj zeptá; nikde se nezobrazí) |
| Složka na souborovém serveru (rozšířené) | Prázdné (domovská složka uživatele), nebo např. `eternus` |
| Ověřovat certifikát souborového serveru (rozšířené) | Vlastní spojení FTPS z acme - vypněte u souborového serveru se self-signed certifikátem |
| Port HTTPS Web GUI (rozšířené) | `443` |
| Poslat s certifikátem i řetězec (nasazení) | Vypnuto (jen certifikát - příručka neříká, že pole řetězec přijme); zkuste jednou zapnout, potřebují-li klienti mezilehlý certifikát |
| Restartovat SMI-S s novým certifikátem (nasazení) | Zapněte jen tam, kde je SMI-S zapnuté a sdílí certifikát Web GUI |
| Zkontrolovat, co se servíruje | Prázdné: Web GUI; pro RESTful API přidejte `dx.example.local:5665` |

## Ověření

- **Vyzkoušet** se přihlásí na souborový server (vypíše složku) a na poli spustí
  `show ssl-version` - nic nemění.
- Po několika minutách:

  ```sh
  openssl s_client -connect dx.example.local:443 -servername dx.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
  openssl s_client -connect dx.example.local:5665 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
  ```

  a v CLI `show events`: nesmí tam být `Network service startup error. service=GUI` (ani
  `service=Restful API`).

## Časté problémy

| Problém | Řešení |
|---|---|
| `the ETERNUS CLI said Error: …` | Přečtěte chybu: špatný uživatel nebo heslo souborového serveru, pole se přes zvolený LAN port k serveru nedostane, server nenabízí FTPS (zvolte *Přenos souborů* přes FTP), nebo klíč a certifikát k sobě nepatří. |
| V událostech `Network service startup error. service=GUI` | Pár byl odmítnut: nasaďte znovu (vynuceně) - acme registruje přes SSH, které funguje i bez HTTPS; nebo `create ssl-certificate` obnoví self-signed certifikát. |
| Řetězec je odmítnut | Vypněte *Poslat s certifikátem i řetězec*. |
| SMI-S servíruje starý certifikát | Zapněte *Restartovat SMI-S s novým certifikátem*, nebo ručně `set smi-s -function disable` / `enable`. |
| `takes RSA keys only` | Změňte typ klíče certifikátu na RSA. |
| Starší pole odmítá `-disable-ftps` | Zvolte *Přenos souborů: FTP na DX S5 / AF S3 / AF S2*. |
