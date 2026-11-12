# TLS server (libovolný port) - nastavení pro acme

Test **TLS (any port)** se připojí na libovolný port, který mluví rovnou TLS - webový server, reverzní proxy, LDAPS, MQTT přes TLS, API, SQL Server s TDS 8.0 strict - a provede TLS handshake se jménem certifikátu jako SNI. Po handshaku se nic neposílá. Poslaný certifikát se porovná s tím, který acme drží. Pro web s HTTP požadavkem použijte **HTTPS**; pro protokoly, které začínají čistým textem, jejich vlastní test (SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL, SQL Server, RDP).

## Co potřebujete

- Server, který na svém portu mluví rovnou TLS se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `443` (nebo vlastní port služby).
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení serveru

1. Nastavte serveru certifikát, klíč a **celý řetězec** (certifikát a za ním mezilehlé):

   nginx:

   ```text
   ssl_certificate     /etc/nginx/tls/fullchain.pem;
   ssl_certificate_key /etc/nginx/tls/privkey.pem;
   ```

   Apache httpd 2.4.8+: `SSLCertificateFile` (celý řetězec) a `SSLCertificateKeyFile`. IIS: **Bindings → https → SSL certificate** webu (u webů se SNI zaškrtnuté *Require Server Name Indication*). HAProxy: `bind :443 ssl crt /etc/haproxy/certs/`.
2. Po každém nasazení server znovu načtěte (příkaz reload v cíli): `systemctl reload nginx`.
3. Každý virtuální host se jmény certifikátu musí odpovídat podle SNI; u serveru za load balancerem testujte každý uzel jeho IP v *Connect to*.
4. Povolte TCP `443` z acme (nebo jeho konektoru):

   ```sh
   firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **TLS (any port)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `443` - nebo vlastní port služby |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí rovnou přes TLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| úvodní text / `the TLS handshake failed` (wrong version number) | port nemluví rovnou TLS: je to čisté HTTP nebo protokol se STARTTLS - použijte test daného protokolu |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
