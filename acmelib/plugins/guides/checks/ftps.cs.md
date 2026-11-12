# FTP server přes TLS (implicitní FTPS) - nastavení pro acme

Test **FTPS** se připojí na port FTP serveru s implicitním TLS (`990`) a hned provede TLS handshake, jako FTP program nastavený na *implicit FTPS*. Nepřihlašuje se. Poslaný certifikát se porovná s tím, který acme drží. Pro FTP na portu 21 s AUTH TLS (explicitní FTPS, běžnější) použijte test **FTP (AUTH TLS)**.

## Co potřebujete

- FTP server s nasloucháním s implicitním TLS se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `990`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení FTP serveru

1. Dejte FTP serveru certifikát, klíč a **celý řetězec** a zapněte TLS:

   vsftpd (`/etc/vsftpd/vsftpd.conf`):

   ```text
   ssl_enable=YES
   rsa_cert_file=/etc/vsftpd/tls/fullchain.pem
   rsa_private_key_file=/etc/vsftpd/tls/privkey.pem
   implicit_ssl=YES
   listen_port=990
   ```

   ProFTPD (mod_tls): `TLSEngine on`, `TLSRSACertificateFile`, `TLSRSACertificateKeyFile`, `TLSCertificateChainFile` a `TLSOptions UseImplicitSSL` ve `<VirtualHost>` s `Port 990`. IIS FTP: **FTP SSL Settings** webu → certifikát (musí být v úložišti Local Computer\Personal).
2. Po každém nasazení službu restartujte (příkaz reload v cíli): `systemctl restart vsftpd`.
3. Povolte TCP `990` z adresy acme (test neotevírá datové spojení, pasivní porty pro něj nehrají roli):

   ```sh
   firewall-cmd --permanent --add-port=990/tcp && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **FTPS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `990` |
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
openssl s_client -connect ftp.example.com:990 -servername ftp.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| text `220`, nebo hned `the TLS handshake failed` | port mluví čisté FTP: použijte test FTP (AUTH TLS), nebo zapněte implicitní TLS (`implicit_ssl=YES`) |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
