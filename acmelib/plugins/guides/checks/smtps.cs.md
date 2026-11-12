# SMTP server přes TLS (SMTPS) - nastavení pro acme

Test **SMTPS** se připojí na port poštovního serveru pro SMTP rovnou přes TLS (implicitní TLS, RFC 8314 - port `465`, *submissions*) a hned provede TLS handshake, jako poštovní program. Po handshaku se nic neposílá; žádná zpráva ani heslo. Poslaný certifikát se porovná s tím, který acme drží. Pro port 25/587 se STARTTLS použijte test **SMTP (STARTTLS)**.

## Co potřebujete

- SMTP server s naslouchajícím portem rovnou přes TLS se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `465`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení poštovního serveru

1. Zapněte naslouchání s implicitním TLS, s certifikátem, klíčem a **celým řetězcem**:

   Postfix (`/etc/postfix/master.cf`, certifikát a klíč v `main.cf` jako `smtpd_tls_cert_file` / `smtpd_tls_key_file`):

   ```text
   submissions inet n - n - - smtpd
     -o smtpd_tls_wrappermode=yes
     -o smtpd_sasl_auth_enable=yes
   ```

   Exim: `tls_on_connect_ports = 465` a `daemon_smtp_ports = 25 : 465 : 587`. Exchange: `Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services SMTP`.
2. Po každém nasazení službu znovu načtěte (příkaz reload v cíli): `systemctl reload postfix`.
3. Povolte TCP `465` z adresy acme:

   ```sh
   firewall-cmd --permanent --add-service=smtps && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **SMTPS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `465` |
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
openssl s_client -connect mail.example.com:465 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the TLS handshake failed` hned, nebo text `220` | port mluví čisté SMTP (STARTTLS), ne rovnou TLS: použijte test SMTP (STARTTLS), nebo zapněte `smtpd_tls_wrappermode` |
| `... does not answer` | služba submissions není v `master.cf` zapnutá, nebo je port zavřený |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
