# Microsoft SQL Server - nastavení pro acme

Test **Microsoft SQL Server** se připojí k SQL Serveru na port `1433`, pošle paket TDS *PRELOGIN* s požadavkem na šifrování, přečte odpověď PRELOGIN a provede TLS handshake přenášený uvnitř paketů TDS - jako SQL Server Management Studio nebo ovladač s *Encrypt*. Nepřihlašuje se. Poslaný certifikát se porovná s tím, který acme drží. SQL Server 2016 - 2022 (a 2025) na Windows i Linuxu. Server nastavený na šifrování TDS 8.0 *strict* mluví rovnou TLS: testujte ho testem **TLS (any port)** na portu 1433.

## Co potřebujete

- SQL Server s certifikátem vybraným pro instanci - obvykle tím, který acme nasazuje do úložiště certifikátů Windows (Local Computer\Personal), nebo na Linuxu do souborů, na které ukazuje `mssql-conf`.
- Síťový přístup **z acme** (nebo jeho konektoru) na TCP `1433` - nebo vlastní statický port instance; pojmenovanou instanci na dynamickém portu tento test přes SQL Browser (UDP 1434) nenajde, dejte jí statický port.
- DNS jméno, které používají klienti, obsažené v certifikátu.

## Nastavení SQL Serveru

1. Windows: certifikát (s klíčem, EKU *Server Authentication*, FQDN serveru) v **Local Computer\Personal**. Dejte účtu služby SQL Server právo číst klíč (certlm.msc → certifikát → All Tasks → Manage Private Keys → přidat `NT Service\MSSQLSERVER` nebo účet služby instance → Read).
2. Vyberte ho pro instanci: **SQL Server Configuration Manager → SQL Server Network Configuration → Protocols for INSTANCE → Properties → Certificate** (INSTANCE: jméno instance, např. MSSQLSERVER) (SQL Server 2019+ také: Import / otisk). Nebo nastavte otisk (malými písmeny, bez mezer) v hodnotě registru `Certificate` pod `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance id>\MSSQLServer\SuperSocketNetLib` - tu může cíl Windows aktualizovat při každém nasazení.
3. **Restartujte službu SQL Server** - SQL Server načítá certifikát jen při startu:

   ```powershell
   Restart-Service -Name MSSQLSERVER -Force
   ```

   Linux: `mssql-conf set network.tlscert /etc/ssl/certs/mssql.pem`, `mssql-conf set network.tlskey /etc/ssl/private/mssql.key`, `systemctl restart mssql-server`.
4. TCP/IP musí být pro instanci zapnuté (Protocols → TCP/IP → Enabled) a TCP `1433` z acme povolený:

   ```powershell
   New-NetFirewallRule -DisplayName 'SQL Server 1433' -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress <acme IP> -Action Allow
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **Microsoft SQL Server**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `1433` |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí, pošle PRELOGIN a provede TLS uvnitř TDS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

Pro TDS nemá `openssl s_client` žádný režim. Na serveru error log SQL Serveru při startu uvádí, který certifikát se načetl:

```powershell
Select-String -Path 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG' -Pattern 'certificate'
```

Měl by říkat `The certificate [Cert Hash(sha1) "<thumbprint>"] was successfully loaded for encryption.` - porovnejte otisk s SHA-1 certifikátu v acme.

## Časté problémy

| Problém | Řešení |
|---|---|
| **another certificate** (self-signed, `CN=SSL_Self_Signed_Fallback`) | pro instanci není vybraný certifikát, nebo účet služby nepřečte jeho klíč - SQL Server použije vlastní; opravte práva ke klíči a restartujte |
| **an old version** | SQL Server se po nasazení nerestartoval |
| `the SQL Server does not do encryption (ENCRYPT_NOT_SUP ...)` | šifrování na instanci není k dispozici: vyberte pro ni certifikát |
| `the server does not speak TDS` | port nepatří SQL Serveru (pojmenovaná instance na jiném portu), nebo TDS 8.0 strict: použijte test TLS |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
