# SIP server přes TLS - nastavení pro acme

Test **SIP over TLS** se připojí k telefonní ústředně nebo SIP proxy na její TLS port (`5061`) a hned provede TLS handshake - certifikát, který by dostal telefon nebo jiná ústředna. Neposílá žádnou SIP zprávu. Poslaný certifikát se porovná s tím, který acme drží. Asterisk (PJSIP), FreeSWITCH, Kamailio, OpenSIPS, 3CX, SBC.

## Co potřebujete

- SIP server s TLS transportem se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `5061`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení SIP serveru

1. Dejte TLS transportu certifikát, klíč a řetězec. Asterisk PJSIP (`pjsip.conf`):

   ```text
   [transport-tls]
   type = transport
   protocol = tls
   bind = 0.0.0.0:5061
   cert_file = /etc/asterisk/keys/fullchain.pem
   priv_key_file = /etc/asterisk/keys/privkey.pem
   method = tlsv1_2
   ```

   FreeSWITCH: `agent.pem` / `cafile.pem` v adresáři `tls` SIP profilu. Kamailio: `tls.cfg` (`certificate`, `private_key`).
2. Po každém nasazení načtěte nové soubory - Asterisk: `asterisk -rx 'module reload res_pjsip.so'` (existující transport si může certifikát držet do restartu: v případě pochybností restartujte).
3. Server nesmí od acme vyžadovat klientský certifikát (Asterisk `verify_client = no`).
4. Povolte TCP `5061` z acme:

   ```sh
   firewall-cmd --permanent --add-port=5061/tcp && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **SIP over TLS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `5061` |
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
openssl s_client -connect sip.example.com:5061 -servername sip.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the TLS handshake failed` (certificate required) | transport vyžaduje klientský certifikát: povolte spojení bez něj |
| **an old version** | transport si nechal starý certifikát: po nasazení SIP server restartujte |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
