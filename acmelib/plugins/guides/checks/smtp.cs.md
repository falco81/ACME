# SMTP server (STARTTLS) - nastavení pro acme

Test **SMTP (STARTTLS)** se připojí k poštovnímu serveru jako jiný poštovní server (nebo poštovní program): přečte uvítání `220`, pošle `EHLO acme-check.<jméno>`, hledá `STARTTLS` mezi rozšířeními, pošle `STARTTLS`, počká na `220` a na stejném spojení provede TLS handshake. Neposílá se žádná zpráva a nepoužívá se heslo. Poslaný certifikát se porovná s tím, který acme drží. Funguje s libovolným SMTP serverem - Postfix, Exim, Sendmail, Microsoft Exchange, appliance. Pro SMTP rovnou přes TLS (port 465) použijte test **SMTPS**.

## Co potřebujete

- SMTP server se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `25` (nebo `587` pro odesílání - submission).
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení poštovního serveru

1. Dejte serveru certifikát a klíč s **celým řetězcem** a nabízejte STARTTLS:

   Postfix (`/etc/postfix/main.cf`):

   ```sh
   postconf -e 'smtpd_tls_cert_file = /etc/postfix/tls/fullchain.pem' \
               'smtpd_tls_key_file = /etc/postfix/tls/privkey.pem' \
               'smtpd_tls_security_level = may'
   systemctl reload postfix
   ```

   Exim: `tls_certificate`, `tls_privatekey` a `tls_advertise_hosts = *`. Exchange (Exchange Management Shell):

   ```powershell
   Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services SMTP
   ```

2. Zařiďte, aby nasazení službu znovu načetlo (příkaz reload/restart v cíli) - běžící Postfix nebo Exim drží starý certifikát, dokud se nenačte znovu.
3. Povolte TCP `25` (a/nebo `587`) z adresy acme ve firewallu hostitele i v síťovém firewallu:

   ```sh
   firewall-cmd --permanent --add-service=smtp && firewall-cmd --reload
   ```

4. Antispam a limity (postscreen, greylisting, `smtpd_client_connection_rate_limit`) nesmějí spojení acme zahodit před EHLO - kde to dělají, dejte IP acme na whitelist.

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **SMTP (STARTTLS)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `25` (`587` pro submission: poštovní programy odesílající s heslem) |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a provede EHLO a STARTTLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls smtp -connect mail.example.com:25 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the server does not offer STARTTLS` | TLS je vypnuté nebo chybí certifikát (Postfix: `smtpd_tls_security_level = may`, soubory cert/key); některé firewally (inspekce SMTP) STARTTLS odstraňují - vypněte to |
| `the SMTP server does not take mail now` | uvítání nebylo `220` (např. `554` - IP acme je blokovaná nebo ji odmítá postscreen): dejte acme na whitelist |
| `the SMTP server refused EHLO` / `refused STARTTLS` | důvod najdete v poštovním logu serveru; zkontrolujte `smtpd_helo_restrictions` a nastavení TLS |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
