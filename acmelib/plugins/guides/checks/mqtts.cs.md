# MQTT broker přes TLS - nastavení pro acme

Test **MQTT over TLS** se připojí na TLS port message brokeru (`8883`) a hned provede TLS handshake - certifikát, který by dostalo zařízení nebo MQTT klient. Neposílá žádný MQTT paket (žádný CONNECT ani přihlašovací údaje). Poslaný certifikát se porovná s tím, který acme drží. Mosquitto, EMQX, HiveMQ, RabbitMQ (plugin MQTT), VerneMQ.

## Co potřebujete

- MQTT broker s TLS listenerem se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `8883`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení MQTT brokeru

1. Dejte TLS listeneru brokeru certifikát, klíč a řetězec. Mosquitto (`/etc/mosquitto/conf.d/tls.conf`):

   ```text
   listener 8883
   certfile /etc/mosquitto/tls/fullchain.pem
   keyfile  /etc/mosquitto/tls/privkey.pem
   ```

   EMQX: `listeners.ssl.default.ssl_options.certfile` / `keyfile`. RabbitMQ: `mqtt.listeners.ssl.default = 8883` a `ssl_options.certfile` / `keyfile` / `cacertfile`.
2. Po každém nasazení proveďte reload (příkaz reload v cíli) - Mosquitto načte certifikáty znovu po `SIGHUP`: `systemctl reload mosquitto`.
3. Klíč musí být čitelný pro uživatele brokeru (`mosquitto`).
4. Povolte TCP `8883` z acme:

   ```sh
   firewall-cmd --permanent --add-port=8883/tcp && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **MQTT over TLS**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `8883` |
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
openssl s_client -connect mqtt.example.com:8883 -servername mqtt.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the TLS handshake failed` (certificate required) | listener vyžaduje klientský certifikát (`require_certificate true`): acme žádný neposílá, testujte listener bez něj, nebo to vypněte |
| `... does not answer` | TLS listener není nastavený nebo je port zavřený |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
