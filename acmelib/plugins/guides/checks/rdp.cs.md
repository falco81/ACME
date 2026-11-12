# Vzdálená plocha (RDP) - nastavení pro acme

Test **RDP (Remote Desktop)** se připojí k serveru Vzdálené plochy na port `3389`, pošle X.224 Connection Request s požadavkem na TLS a CredSSP (NLA), přečte Connection Confirm a na stejném spojení provede TLS handshake - certifikát, který by dostalo *Připojení ke vzdálené ploše*. Nepřihlašuje se (CredSSP není potřeba: certifikát je vidět už v TLS handshaku). Poslaný certifikát se porovná s tím, který acme drží. Windows Server 2012 R2 - 2025 a Windows 10/11, nebo jiný RDP server (xrdp). RD Gateway a RD Web jsou HTTPS: použijte pro ně test **HTTPS**.

## Co potřebujete

- Zapnutou Vzdálenou plochu s certifikátem, který acme nasazuje (na Windows Local Computer\Personal), vybraným jako certifikát RDP listeneru - cíl Windows ho může nastavit při každém nasazení.
- Vrstva zabezpečení musí být **TLS** nebo **Negotiate**, ne *RDP Security Layer* (standardní zabezpečení RDP nemá žádný certifikát k testu).
- Síťový přístup **z acme** (nebo jeho konektoru) na TCP `3389`.

## Nastavení Vzdálené plochy

1. Importujte certifikát (s klíčem, EKU *Server Authentication*, FQDN serveru) do **Local Computer\Personal** a dejte `NETWORK SERVICE` právo číst jeho klíč (certlm.msc → All Tasks → Manage Private Keys).
2. Nasměrujte na něj RDP listener podle otisku:

   ```powershell
   $tp = '<thumbprint>'
   $ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
   Set-CimInstance -InputObject $ts -Property @{SSLCertificateSHA1Hash = $tp}
   ```

   Restart není potřeba - nová spojení dostanou nový certifikát. (Certifikát může vybrat i Group Policy: *Remote Desktop Session Host → Security → Server authentication certificate template* - politika má přednost před nastavením výše.)
3. Vrstva zabezpečení: Group Policy **Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → Require use of specific security layer for remote (RDP) connections** = *SSL* nebo *Negotiate* (nebo nenastaveno).
4. Povolte TCP `3389` z acme:

   ```powershell
   Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
   ```

   xrdp: `certificate=` a `key_file=` v `/etc/xrdp/xrdp.ini`, `security_layer=tls` nebo `negotiate`, pak `systemctl restart xrdp`.

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **RDP (Remote Desktop)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `3389` |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a provede vyjednání RDP a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

Na serveru otisk, který listener používá:

```powershell
(Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'").SSLCertificateSHA1Hash
```

Musí se rovnat SHA-1 otisku certifikátu v acme (`openssl s_client` režim pro RDP nemá).

## Časté problémy

| Problém | Řešení |
|---|---|
| `the RDP server uses standard RDP security - no TLS` | vrstva zabezpečení je *RDP Security Layer*: nastavte *SSL* nebo *Negotiate* |
| `the RDP server refused TLS: ...` | důvod je uveden (např. `SSL_CERT_NOT_ON_SERVER` - vybraný certifikát chybí nebo nejde číst jeho klíč) |
| **another certificate** (`CN=<jméno počítače>`, self-signed) | listener stále používá svůj self-signed certifikát: nastavte `SSLCertificateSHA1Hash`, ověřte, že `NETWORK SERVICE` čte klíč; může ho přebíjet šablona z GPO |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
