# Webový server (HTTPS) - nastavení pro acme

Test **HTTPS** se připojí k webovému serveru (port `443` nebo jiný), provede TLS handshake se jménem certifikátu jako SNI - certifikát, který by dostal prohlížeč - a když je zapnuté *Ask over HTTP too*, pošle HTTP požadavek (HEAD, GET nebo OPTIONS, zvolená cesta a hlavička Host) a zkontroluje stav a slova odpovědi. Poslaný certifikát se porovná s tím, který acme drží. Libovolný webový server, reverzní proxy, load balancer nebo zařízení s webovým rozhraním.

## Co potřebujete

- Webový server se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `443`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení webového serveru

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
5. S *Ask over HTTP too*: dotazovaná cesta (např. `/health`) musí odpovídat bez přihlášení se stavem mezi očekávanými; WAF nesmí požadavek blokovat (`User-Agent` lze nastavit v *More headers*).

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **HTTPS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `443` |
| Name asked for (SNI) | prázdné: první jméno certifikátu; `-`: SNI se neposílá (servery, které certifikát podle jména nevybírají) |
| Name the certificate must hold | prázdné: SNI; vyplňte, když se připojujete na IP, ale certifikát nese DNS jméno |
| Ask over HTTP too | zapněte, chcete-li ověřit, že web odpovídá, ne jen jeho certifikát |
| Method / Path | `HEAD` (výchozí) nebo `GET`, `OPTIONS`; cesta, např. `/` nebo `/health` |
| Host header | prázdné: SNI; virtuální host jiný než SNI |
| More headers | `Jméno: hodnota`, jedna na řádek |
| Status expected | `200-399` (výchozí), např. `200,301-302`; prázdné: jakákoli |
| The answer holds | slova, která odpověď musí obsahovat (jen GET, prvních 64 KB) |
| The certificate expected | *the version deployed now* (výchozí); *any version* jen tam, kde starší verze není chyba |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* nebo *both* pro server s duálním (RSA + ECDSA) certifikátem - server musí umět TLS 1.2 |
| Check the chain sent | zapnuto - server musí posílat i mezilehlé certifikáty |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (pokročilé) | obvykle prázdné |
| Time limit (s) (pokročilé) | `15`; u pomalého serveru zvyšte |
| Fail when not trusted here (pokročilé) | zapnuto pro veřejnou CA; vypnuto pro certifikát vlastní CA, pokud stroj s acme nedůvěřuje jejímu kořeni |
| Through a connector (pokročilé) | *directly*, nebo *Connector over SSH*, když se k serveru dostane jen jiná síť |

## Ověření

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí (a pošle HTTP požadavek, je-li to nastaveno) a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

```sh
curl -sSI https://www.example.com/health
```

## Časté problémy

| Problém | Řešení |
|---|---|
| **wrong answer** | stav nebo slova neodpovídají nastavení: zkontrolujte cestu, hlavičku Host, přesměrování (přidejte `301-302`), nebo WAF, který požadavek blokuje |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
