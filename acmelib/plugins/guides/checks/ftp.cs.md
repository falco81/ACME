# FTP server (AUTH TLS, explicitní FTPS) - nastavení pro acme

Test **FTP (AUTH TLS)** se připojí k FTP serveru na port `21` jako FTP program: přečte uvítání `220`, pošle `AUTH TLS` a na stejném spojení provede TLS handshake (explicitní FTPS, RFC 4217). Nepřihlašuje se a neotevírá datové spojení. Poslaný certifikát se porovná s tím, který acme drží. Funguje s vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, IIS FTP. Pro FTPS rovnou přes TLS na portu 990 použijte test **FTPS**.

## Co potřebujete

- FTP server se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `21`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení FTP serveru

1. Dejte FTP serveru certifikát, klíč a **celý řetězec** a zapněte TLS:

   vsftpd (`/etc/vsftpd/vsftpd.conf`):

   ```text
   ssl_enable=YES
   rsa_cert_file=/etc/vsftpd/tls/fullchain.pem
   rsa_private_key_file=/etc/vsftpd/tls/privkey.pem
   ```

   ProFTPD (mod_tls): `TLSEngine on`, `TLSRSACertificateFile`, `TLSRSACertificateKeyFile`, `TLSCertificateChainFile`. IIS FTP: **FTP SSL Settings** webu → certifikát (musí být v úložišti Local Computer\Personal).
2. Po každém nasazení službu restartujte (příkaz reload v cíli): `systemctl restart vsftpd`.
3. Povolte TCP `21` z adresy acme (test neotevírá datové spojení, pasivní porty pro něj nehrají roli):

   ```sh
   firewall-cmd --permanent --add-port=21/tcp && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **FTP (AUTH TLS)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `21` |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a pošle AUTH TLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls ftp -connect ftp.example.com:21 -servername ftp.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AUTH TLS` odmítnuto (`500`/`502`/`534`) | TLS není ve FTP serveru zapnuté (`ssl_enable=YES`, `TLSEngine on`) |
| uvítání není `220` | server odmítá adresu acme (`tcp_wrappers`, limit počtu klientů): povolte acme |
| FTP firewall po cestě | některé firewally (inspekce FTP / ALG) AUTH TLS rozbíjejí: vypněte inspekci pro tento server |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
