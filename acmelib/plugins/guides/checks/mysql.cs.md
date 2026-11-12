# MySQL / MariaDB - nastavení pro acme

Test **MySQL / MariaDB** se připojí k databázovému serveru na port `3306`, přečte jeho uvítání (Initial Handshake Packet) a ověří, že nabízí TLS (`CLIENT_SSL`), odpoví paketem *SSLRequest* - bez uživatele a hesla - a provede TLS handshake, jako klient `mysql` nebo ovladač. Poslaný certifikát se porovná s tím, který acme drží. MySQL 5.7 / 8.x a MariaDB 10.x / 11.x.

## Co potřebujete

- Server MySQL nebo MariaDB se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `3306`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení MySQL / MariaDB

1. Dejte certifikát, klíč a řetězec CA tam, odkud je server čte, do `[mysqld]` (`/etc/my.cnf.d/server.cnf` nebo `/etc/mysql/my.cnf`):

   ```text
   [mysqld]
   ssl_cert = /etc/mysql/tls/fullchain.pem
   ssl_key  = /etc/mysql/tls/privkey.pem
   ssl_ca   = /etc/mysql/tls/chain.pem
   ```

   Soubory musí být čitelné pro uživatele `mysql`.
2. Po každém nasazení načtěte nové soubory (příkaz reload v cíli) - bez restartu:

   ```sh
   mysql -e 'ALTER INSTANCE RELOAD TLS;'   # MySQL 8.0.16+
   mariadb -e 'FLUSH SSL;'                 # MariaDB 10.4+
   ```

   Starší verze: restartujte službu.
3. `bind-address` musí obsahovat adresu, na kterou se acme připojuje; povolte TCP `3306` z acme:

   ```sh
   firewall-cmd --permanent --add-service=mysql && firewall-cmd --reload
   ```

4. `max_connect_errors` v MySQL počítá handshaky bez přihlášení: když se IP acme *zablokuje kvůli mnoha chybám spojení*, zvyšte ho nebo spusťte `FLUSH HOSTS` (MySQL 8: `TRUNCATE performance_schema.host_cache`).

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **MySQL / MariaDB**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `3306` |
| Name asked for (SNI) | prázdné: první jméno certifikátu; `-`: SNI se neposílá (servery, které certifikát podle jména nevybírají) |
| Name the certificate must hold | prázdné: SNI; vyplňte, když se připojujete na IP, ale certifikát nese DNS jméno |
| The certificate expected | *the version deployed now* (výchozí); *any version* jen tam, kde starší verze není chyba |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* nebo *both* pro server s duálním (RSA + ECDSA) certifikátem - server musí umět TLS 1.2 |
| Check the chain sent | zapnuto - server musí posílat i mezilehlé certifikáty |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (pokročilé) | obvykle prázdné |
| Time limit (s) (pokročilé) | `15`; u pomalého serveru zvyšte |
| Fail when not trusted here (pokročilé) | zapnuto pro veřejnou CA; vypnuto pro certifikát vlastní CA, pokud stroj s acme nedůvěřuje jejímu kořeni |
| Through a connector (pokročilé) | *directly*, nebo *Connector over SSH*, když se k serveru dostane jen jiná síť |

## Ověření

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a pošle SSLRequest a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls mysql -connect db.example.com:3306 -servername db.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls mysql` potřebuje OpenSSL 1.1.1 nebo novější.) Na serveru: `mysql -e "SHOW VARIABLES LIKE '%ssl%';"`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the MySQL server does not offer TLS (... without CLIENT_SSL ...)` | není nastaven certifikát, nebo je `have_ssl` `DISABLED` (soubory nešly přečíst - viz error log) |
| `the MySQL server refused the connection (error 1130 / 1129 ...)` | 1130: hostitel acme se nesmí připojit vůbec; 1129: zablokováno po mnoha chybách spojení - `FLUSH HOSTS`, zvyšte `max_connect_errors` |
| **an old version** | nové soubory se nenačetly: `ALTER INSTANCE RELOAD TLS` / `FLUSH SSL`, nebo restart |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
