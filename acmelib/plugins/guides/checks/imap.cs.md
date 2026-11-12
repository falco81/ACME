# IMAP server (STARTTLS) - nastavení pro acme

Test **IMAP (STARTTLS)** se připojí k poštovnímu serveru na port `143` jako poštovní program: přečte uvítání, zeptá se `CAPABILITY`, hledá `STARTTLS`, pošle `STARTTLS` a na stejném spojení provede TLS handshake. Nepřihlašuje se. Poslaný certifikát se porovná s tím, který acme drží. Funguje s Dovecotem, Cyrem, Exchange a libovolným IMAP serverem. Pro IMAP rovnou přes TLS (port 993) použijte test **IMAPS**.

## Co potřebujete

- IMAP server se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `143`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení poštovního serveru

1. Dejte serveru certifikát, klíč a **celý řetězec** a zapněte TLS:

   Dovecot 2.3 (`/etc/dovecot/conf.d/10-ssl.conf`; Dovecot 2.4 je jmenuje `ssl_server_cert_file` / `ssl_server_key_file`):

   ```text
   ssl = yes
   ssl_cert = </etc/dovecot/tls/fullchain.pem
   ssl_key = </etc/dovecot/tls/privkey.pem
   ```

   Pak `systemctl reload dovecot`. Exchange: `Enable-ExchangeCertificate -Thumbprint <thumbprint> -Services IMAP4` a restart služeb Exchange IMAP4.

2. Zařiďte, aby nasazení službu znovu načetlo (příkaz reload v cíli) - Dovecot drží starý certifikát, dokud se nenačte znovu.
3. Povolte TCP `143` z adresy acme:

   ```sh
   firewall-cmd --permanent --add-service=imap && firewall-cmd --reload
   ```
4. fail2ban a podobné nesmějí acme zablokovat: připojuje se bez přihlášení, každých pár hodin, když testy běží samy.

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **IMAP (STARTTLS)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `143` |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a provede CAPABILITY a STARTTLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls imap -connect mail.example.com:143 -servername mail.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the server does not offer STARTTLS` | TLS je vypnuté nebo nemá certifikát (Dovecot: `ssl = yes`; `ssl = required` ho nabízí také); podívejte se do logu serveru |
| `... closed the session` / odpověď `NO`/`-ERR` | server odmítá adresu acme (jail fail2ban, seznam povolených IP): dejte acme na whitelist |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
