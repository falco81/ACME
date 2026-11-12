# Traefik Proxy (file provider) - nastavení pro acme

acme se k hostiteli Traefiku přihlásí přes SSH a zapíše:

- certifikát (celý řetězec) a klíč jako `acme-<jméno>-<datum>-<sériové číslo>.crt` / `.key`
  do *Folder for the certificates*;
- soubor dynamické konfigurace `acme-<jméno>.yml` do **složky file provideru**, který je
  uvádí v `tls.certificates` (a na přání i jako `tls.stores.default.defaultCertificate`).

Traefik složku sleduje a nový certifikát převezme **bez restartu**. Starší soubory
certifikátů nad počet *Previous versions to keep* se smažou.

Pro Traefik Proxy v2 a v3, nainstalovaný přímo na hostiteli nebo v kontejneru.

## Co potřebujete

- SSH z acme na hostitele Traefiku, **TCP 22**.
- `root`, nebo uživatele se `sudo`, který smí zapisovat do obou složek.
- Traefik spuštěný s **file providerem, který sleduje složku**.

## Nastavení Traefiku a hostitele

1. Zapněte file provider s `watch` ve statické konfiguraci Traefiku, např.
   `/etc/traefik/traefik.yml`:

   ```text
   providers:
     file:
       directory: /etc/traefik/dynamic
       watch: true
   ```

   nebo jako argumenty: `--providers.file.directory=/etc/traefik/dynamic --providers.file.watch=true`.
   Po přidání Traefik jednou restartujte.
2. Vytvořte složky:

   ```sh
   sudo mkdir -p /etc/traefik/certs /etc/traefik/dynamic
   ```

3. **Traefik v Dockeru**: připojte obě složky (jako složky, ne jednotlivé soubory) do
   kontejneru, např. `-v /etc/traefik/certs:/certs:ro -v /etc/traefik/dynamic:/etc/traefik/dynamic:ro`,
   a v acme nastavte *The certificates' folder as Traefik sees it* na `/certs`.
4. Vytvořte účet pro acme a vložte k němu veřejný klíč acme (*The SSH key → How to set it
   up* v acme ukáže příkazy); není-li to root, povolte sudo bez hesla - acme spouští kroky
   jako `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **Pro tento účet to znamená root.** Případně dejte účtu obě složky do vlastnictví a
   *Use sudo* nechte vypnuté.
5. Routery potřebují `tls: {}` (nebo label `tls=true`) - Traefik pak vybere certifikát,
   jehož jména odpovídají požadavku.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / SSH port / User | Hostitel Traefiku, `22`, `acme` (nebo `root`) |
| Sign in with / The SSH key | *a private key* |
| Use sudo / sudo password | Zapnout pro účet, který není root; heslo prázdné při `NOPASSWD` |
| Folder for the certificates (nasazení) | `/etc/traefik/certs` |
| Folder of the file provider (nasazení) | `/etc/traefik/dynamic` - `providers.file.directory` |
| The certificates' folder as Traefik sees it (pokročilé) | Pro kontejner, např. `/certs`; prázdné: stejná cesta |
| Also the default certificate (nasazení) | Zapnout, má-li se použít, když žádný jiný certifikát nesedí |
| Previous versions to keep (pokročilé) | Výchozí 1, `-1` ponechá vše |
| Check what is served | např. `www.example.com:443` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí a hledá `traefik version` nebo kontejner
  Traefiku: `signed in as acme; Version: 3.x ...`.
- Na hostiteli:

  ```sh
  cat /etc/traefik/dynamic/acme-*.yml
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

- Log Traefiku na úrovni DEBUG ukazuje, jak file provider znovu načítá konfiguraci.

## Časté problémy

| Problém | Řešení |
|---|---|
| Traefik dál ukazuje svůj výchozí certifikát | File provider tu složku nesleduje (`watch: true`), nebo router nemá `tls`. |
| `... is not an absolute path without spaces` | Použijte absolutní cesty bez mezer a znaků shellu. |
| V logu Traefiku: soubor nenalezen | Traefik v kontejneru vidí jinou cestu: nastavte *The certificates' folder as Traefik sees it*. |
| V Dockeru se změny neprojeví | Je připojen jednotlivý soubor místo složky - připojte složku. |
| Permission denied při zápisu | Zapněte *Use sudo*, nebo dejte účtu obě složky. |
