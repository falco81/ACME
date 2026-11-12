# XMPP server (STARTTLS) - nastavení pro acme

Test **XMPP (STARTTLS)** se připojí k chatovacímu (Jabber) serveru na port `5222`, otevře klientský stream k XMPP doméně, přečte stream features, požádá o `<starttls/>`, počká na `<proceed/>` a na stejném spojení provede TLS handshake (RFC 6120) - certifikát, který by dostal chatovací klient. Nepřihlašuje se. Poslaný certifikát se porovná s tím, který acme drží. Funguje s Prosody, ejabberd, Openfire a dalšími XMPP servery.

## Co potřebujete

- XMPP server s certifikátem pro XMPP doménu (a jeho komponenty `conference.`, `upload.`, pokud jsou jmény certifikátu).
- Síťový přístup **z acme** (nebo jeho konektoru) na TCP `5222` (server-server je `5269`, ten se zde netestuje).
- XMPP doménu - část adres za `@`; certifikát ji musí obsahovat.

## Nastavení XMPP serveru

1. Dejte serveru certifikát, klíč a **celý řetězec**:

   Prosody - dejte je do `/etc/prosody/certs/` (pojmenované podle domény, `example.com.crt` / `example.com.key`) nebo je importujte:

   ```sh
   prosodyctl --root cert import /etc/acme-deploy/example.com/
   prosodyctl reload
   ```

   ejabberd (`ejabberd.yml`):

   ```text
   certfiles:
     - /etc/ejabberd/tls/example.com.pem
   ```

   pak `ejabberdctl reload_config`. Openfire: Server → TLS/SSL Certificates → identity store.
2. STARTTLS musí být nabízeno na c2s (Prosody `c2s_require_encryption = true` ho nabízí také; ejabberd `starttls: true` nebo `starttls_required: true` na listeneru 5222).
3. Soubor s klíčem musí být čitelný pro uživatele serveru (`prosody`, `ejabberd`).
4. Povolte TCP `5222` z acme:

   ```sh
   firewall-cmd --permanent --add-service=xmpp-client && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **XMPP (STARTTLS)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `5222` |
| Name asked for (SNI) | prázdné: první jméno certifikátu; `-`: SNI se neposílá (servery, které certifikát podle jména nevybírají) |
| Name the certificate must hold | prázdné: SNI; vyplňte, když se připojujete na IP, ale certifikát nese DNS jméno |
| XMPP domain | doména, ke které se stream otevírá (za `@` v adresách). Prázdné: SNI, jinak adresa |
| The certificate expected | *the version deployed now* (výchozí); *any version* jen tam, kde starší verze není chyba |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* nebo *both* pro server s duálním (RSA + ECDSA) certifikátem - server musí umět TLS 1.2 |
| Check the chain sent | zapnuto - server musí posílat i mezilehlé certifikáty |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (pokročilé) | obvykle prázdné |
| Time limit (s) (pokročilé) | `15`; u pomalého serveru zvyšte |
| Fail when not trusted here (pokročilé) | zapnuto pro veřejnou CA; vypnuto pro certifikát vlastní CA, pokud stroj s acme nedůvěřuje jejímu kořeni |
| Through a connector (pokročilé) | *directly*, nebo *Connector over SSH*, když se k serveru dostane jen jiná síť |

## Ověření

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí, otevře stream a požádá o STARTTLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls xmpp -xmpphost example.com -connect chat.example.com:5222 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

U Prosody také: `prosodyctl check certs`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the server does not offer STARTTLS` | TLS je pro c2s vypnuté, nebo pro doménu chybí certifikát: zkontrolujte nastavení listeneru |
| `the XMPP server ended the stream: host-unknown` | *XMPP domain* není doména, kterou server hostuje: nastavte doménu za `@` |
| **another certificate** | server vybral certifikát jiného virtuálního hostitele: nastavte správnou XMPP doménu / SNI |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
