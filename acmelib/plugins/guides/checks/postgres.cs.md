# PostgreSQL - nastavení pro acme

Test **PostgreSQL** se připojí k serveru PostgreSQL na port `5432` a pošle 8bajtový *SSLRequest*; server odpoví jedním bajtem - `S` (následuje TLS) nebo `N` (SSL je vypnuté) - a při `S` acme provede TLS handshake, jako `psql` nebo ovladač se `sslmode=require`. Nepřihlašuje se, takže `pg_hba.conf` a hesla nehrají roli. Poslaný certifikát se porovná s tím, který acme drží. Libovolná podporovaná verze PostgreSQL (a kompatibilní servery: pgBouncer s `client_tls_*`, uzly Patroni).

## Co potřebujete

- Server PostgreSQL se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `5432`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení PostgreSQL

1. Dejte certifikát (s **mezilehlými za ním** ve stejném souboru) a klíč tam, odkud je PostgreSQL čte, a v `postgresql.conf` zapněte SSL:

   ```text
   ssl = on
   ssl_cert_file = '/var/lib/pgsql/data/server.crt'
   ssl_key_file = '/var/lib/pgsql/data/server.key'
   ```

2. Klíč musí patřit uživateli serveru a nesmí být čitelný pro ostatní:

   ```sh
   chown postgres:postgres /var/lib/pgsql/data/server.{crt,key}
   chmod 0600 /var/lib/pgsql/data/server.key
   ```

3. Po každém nasazení proveďte reload (PostgreSQL 10+ převezme nové soubory certifikátu při reloadu; příkaz reload v cíli):

   ```sh
   sudo -u postgres psql -c 'SELECT pg_reload_conf();'
   ```

4. `listen_addresses` musí obsahovat adresu, na kterou se acme připojuje (ne jen `localhost`), a TCP `5432` musí být z acme povolený:

   ```sh
   firewall-cmd --permanent --add-service=postgresql && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **PostgreSQL**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `5432` |
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
openssl s_client -starttls postgres -connect db.example.com:5432 -servername db.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls postgres` potřebuje OpenSSL 1.1.1 nebo novější.) Na serveru: `psql -c 'SHOW ssl;'` vrátí `on`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `SSL is off on the PostgreSQL server (it answered N ...)` | `ssl = off` (nebo se soubory nenačetly - viz log serveru): nastavte `ssl = on` a proveďte reload |
| `refused the SSLRequest (an error message ...)` | server příliš starý pro SSL, nebo na portu běží něco jiného |
| **an old version** | server se po nasazení nenačetl znovu (`SELECT pg_reload_conf();`) |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
