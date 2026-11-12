# TrueNAS - nastavení pro acme

acme se k TrueNAS přihlásí přes SSH a použije klienta middlewaru (`midclt`, nebo
pythonového klienta middlewaru) přímo na stroji - funguje tedy i na verzích, kde je REST API
zastaralé nebo odstraněné. Naimportuje certifikát pod jménem s datem
(`certificate.create`, `CERTIFICATE_CREATE_IMPORTED`), nastaví ho jako **certifikát
webového rozhraní** (`system.general.update` `ui_certificate`, pak
`system.general.ui_restart`) a na přání jako **certifikát FTP** (`ftp.update`
`ssltls_certificate`) a smaže starší certifikáty acme nad počet *Previous versions to
keep* (ten, který se ještě používá, zůstane). Soukromý klíč se nikdy neobjeví na
příkazové řádce.

Pro TrueNAS SCALE / Community Edition (24.04 a novější) a TrueNAS CORE.

## Co potřebujete

- SSH z acme na TrueNAS, **TCP 22**.
- `root`, nebo správce se sudo - `truenas_admin` na SCALE 24.04 a novějších (přihlášení
  roota je tam ve výchozím stavu vypnuté).

## Nastavení TrueNAS

1. Zapněte SSH: **System → Services → SSH** → zapnout a *Start Automatically*. V jeho
   nastavení nechte *Allow Password Authentication* vypnuté, pokud používáte klíč
   (doporučeno).
2. Vložte veřejný klíč acme ke správci: **Credentials → Users → truenas_admin → Edit →
   Authorized Keys** (CORE: **Accounts → Users → Edit → SSH Public Key**). Klíč nejdřív
   vytvořte v acme (cíl → *The SSH key* → *Make a key*).
3. Povolte uživateli sudo bez hesla - acme spouští kroky jako `sudo -n sh -c ...`: na
   stránce úpravy uživatele zaškrtněte **Allow all sudo commands with no password** (nebo
   přidejte `sh` do *Allowed sudo commands with no password*). **Znamená to root.** (Nebo
   se přihlašujte jako `root` a *Use sudo* nechte vypnuté.)
4. Je-li webové rozhraní TrueNAS za firewallem / seznamem povolených adres, musí být z acme
   dostupný i port SSH.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP NAS |
| SSH port | `22` |
| User | `truenas_admin` (výchozí) nebo `root` |
| Sign in with / The SSH key | *a private key* - klíč z kroku 2 |
| Use sudo / sudo password | Zapnout pro `truenas_admin`; heslo prázdné při sudo „no password“ |
| Host key (pokročilé) | Řádek `known_hosts`, nebo prázdné se zapnutým *Trust the first host key seen* |
| Web interface certificate (nasazení) | Zapnuto (výchozí) |
| FTP certificate (nasazení) | Zapnout, má-li ho používat FTP s TLS |
| Previous versions to keep (pokročilé) | Výchozí 1, `-1` ponechá vše |
| Check what is served | Prázdné: acme ověří webové rozhraní na portu 443 |

## Ověření

- Na cíli stiskněte **Try**: acme spustí `midclt call system.version`, vypíše certifikáty a
  odpoví `signed in: TrueNAS-..., N certificates`.
- Na TrueNAS (shell):

  ```sh
  sudo midclt call system.general.config | python3 -m json.tool | grep -A3 ui_certificate
  ```

- Ve webovém rozhraní: **Credentials → Certificates** obsahuje `acme-...`; **System →
  General Settings → GUI** ho ukazuje.

## Časté problémy

| Problém | Řešení |
|---|---|
| `Permission denied (publickey)` | Klíč není v *Authorized Keys* uživatele, nebo nastavení služby SSH. |
| `sudo: a password is required` / midclt odmítnut | Zaškrtněte *Allow all sudo commands with no password*, nebo vyplňte *sudo password*. |
| `midclt: command not found` | Nejde o shell TrueNAS, nebo ho PATH neobsahuje - použijte sudo/root. |
| `TrueNAS does not list ... after importing it` | Import tiše selhal - podívejte se do *Credentials → Certificates* a do logu middlewaru `/var/log/middlewared.log`. |
| `the old ... stays (still used?)` | Používá ho jiná služba (S3, WebDAV, aplikace); přepněte ji a příště zmizí. |
| Webové rozhraní je chvíli nedostupné | Očekávané: po změně se restartuje. |
