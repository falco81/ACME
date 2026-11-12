# Resolver DNS over TLS - nastavení pro acme

Test **DNS over TLS** se připojí na port DoT DNS resolveru (`853`, RFC 7858) a hned provede TLS handshake - certifikát, který by dostal systémový resolver nebo telefon (Soukromé DNS). Neposílá žádný DNS dotaz. Poslaný certifikát se porovná s tím, který acme drží. Unbound, Knot Resolver, BIND 9.18+, dnsdist, AdGuard Home, Technitium.

## Co potřebujete

- Resolver se zapnutým DNS over TLS se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `853`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení resolveru

1. Dejte resolveru certifikát, klíč a řetězec. Unbound (`unbound.conf`):

   ```text
   server:
     interface: 0.0.0.0@853
     tls-port: 853
     tls-service-pem: "/etc/unbound/tls/fullchain.pem"
     tls-service-key: "/etc/unbound/tls/privkey.pem"
   ```

   BIND 9.18+: blok `tls` (`cert-file`, `key-file`) a `listen-on port 853 tls <jméno> { any; };`. Knot Resolver: `net.tls('/cesta/fullchain.pem', '/cesta/privkey.pem')`. dnsdist: `addTLSLocal('0.0.0.0:853', cert, key)`.
2. Po každém nasazení proveďte reload (příkaz reload v cíli) - Unbound potřebuje pro nové TLS soubory restart: `systemctl restart unbound`.
3. Povolte TCP `853` z acme:

   ```sh
   firewall-cmd --permanent --add-service=dns-over-tls && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **DNS over TLS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `853` |
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
openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

`kdig +tls @dns.example.com example.com` (dig od Knotu) položí skutečný dotaz přes TLS.

## Časté problémy

| Problém | Řešení |
|---|---|
| `... does not answer` | DoT není zapnuté (Unbound: chybí `interface ...@853`) nebo je port 853 zavřený |
| **an old version** | resolver se po nasazení nerestartoval |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
