# Caddy - nastavení pro acme

acme se k serveru s Caddy přihlásí přes **SSH** a udělá jedno ze dvou:

- **admin API** (výchozí): přes `curl` na serveru zavolá admin API Caddy
  (`localhost:2019`) a nahradí položky `apps.tls.certificates.load_pem` označené
  `acme-<jméno>` (`PATCH`, nebo `POST`, když tam ještě žádné nejsou). Žádný soubor, žádný
  reload. Pro Caddy spuštěné z **JSON konfigurace** nebo s `--resume` - reload Caddyfile ho
  ztratí.
- **soubory + reload**: zapíše certifikát a klíč do cest, které uvádí řádek `tls` ve
  vašem Caddyfile, a spustí `caddy reload` (selže-li reload, vrátí staré soubory).

Pro Caddy 2.x na Linuxu.

## Co potřebujete

- Přístup SSH z acme na server (výchozí TCP 22).
- Na serveru nainstalovaný `curl`.
- **Zapnuté admin rozhraní** Caddy (výchozí `localhost:2019`; ne `admin off`) - **Try**
  ho čte v obou režimech.
- Pro *soubory + reload*: uživatele, který smí zapsat soubory certifikátu a spustit
  reload (root, nebo uživatel se sudo).

## Nastavení serveru s Caddy

1. Vytvořte pro acme uživatele a vložte veřejný SSH klíč acme do jeho
   `~/.ssh/authorized_keys` (klíč vytvoří acme: pole *The SSH key*).

   ```sh
   sudo useradd -m -s /bin/bash acme
   sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' | sudo tee /home/acme/.ssh/authorized_keys
   ```

2. Pro **admin API**: nic dalšího - ověřte, že admin API lokálně odpovídá:

   ```sh
   curl -s http://localhost:2019/config/apps/tls/certificates
   ```

3. Pro **soubory + reload**: uveďte soubory v Caddyfile a nechte acme je zapsat a Caddy
   znovu načíst. U uživatele, který není root, povolte přes sudo jen to potřebné, např.
   `/etc/sudoers.d/acme`:

   ```text
   www.example.com {
       tls /etc/caddy/certs/www.example.com.crt /etc/caddy/certs/www.example.com.key
   }
   ```

   ```sh
   sudo install -d -m 750 -o caddy -g caddy /etc/caddy/certs
   echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme   # zužte, pokud můžete
   ```

   acme zapisuje soubory přes sudo, nastavuje jejich vlastníka a spouští příkaz reload;
   užší pravidlo sudoers musí stále povolit zápis souborů a `caddy reload`.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP serveru |
| SSH port / User | `22` / `acme` (nebo `root`) |
| Sign in with / The SSH key / Password | Klíč vytvořený v acme (doporučeno) nebo heslo |
| Use sudo / sudo password | Zapnuto, když uživatel není root (prázdné heslo: NOPASSWD) |
| Admin API on the machine | Adresa `admin` Caddy, výchozí `localhost:2019` |
| How (nasazení) | `admin API: load_pem, no reload (JSON config)` nebo `files + reload (Caddyfile)` |
| Certificate file / Key file (nasazení) | Cesty z řádku `tls`, např. `/etc/caddy/certs/{name}.crt` |
| Owner of the files (nasazení) | Výchozí `caddy:caddy` |
| Reload (nasazení) | Výchozí `caddy reload --config /etc/caddy/Caddyfile` |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Volby práce se soubory v režimu souborů |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try**: `signed in; Caddy's admin API answers, N certificates loaded through it`.
- Na serveru:

  ```sh
  curl -s http://localhost:2019/config/apps/tls/certificates | head
  journalctl -u caddy --since "10 min ago"
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| curl nenalezen | Nainstalujte na server `curl` |
| Spojení na `localhost:2019` odmítnuto | Admin API je vypnuté nebo na jiné adrese - opravte *Admin API on the machine* |
| Certifikát po `caddy reload` zmizel | Používáte Caddyfile: místo admin API použijte *files + reload* |
| Permission denied při zápisu souborů | Zapněte *Use sudo* nebo dejte uživateli práva k adresáři |
| Reload selže | Zkontrolujte Caddyfile (`caddy validate --config /etc/caddy/Caddyfile`); acme vrátilo staré soubory |
| Změněný klíč hostitele | Po přeinstalaci serveru aktualizujte *Host key* |
