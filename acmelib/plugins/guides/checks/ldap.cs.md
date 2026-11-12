# LDAP server (StartTLS) - nastavení pro acme

Test **LDAP (StartTLS)** se připojí k adresářovému serveru na port `389` a jako zprávu 1 pošle rozšířený požadavek StartTLS (OID `1.3.6.1.4.1.1466.20037`); při výsledku `0` (success) provede na stejném spojení TLS handshake. Neprovádí bind (žádný uživatel ani heslo). Poslaný certifikát se porovná s tím, který acme drží. Funguje s OpenLDAP, 389 Directory Server / Red Hat DS / FreeIPA a řadiči domény Active Directory. Pro LDAP rovnou přes TLS (port 636) použijte test **LDAPS**.

## Co potřebujete

- Adresářový server se zapnutým TLS a nastaveným certifikátem - obvykle soubory, které tam nasazuje acme (cíl Linux / Unix (SSH), cíl Windows...).
- Síťový přístup **z acme** (nebo z konektoru, přes který jde) na server, TCP port `389`.
- DNS jméno, které používají klienti, obsažené v certifikátu; acme ho posílá jako SNI.

## Nastavení adresářového serveru

1. Dejte adresářovému serveru certifikát, klíč a **celý řetězec**:

   OpenLDAP (`cn=config`):

   ```sh
   ldapmodify -Y EXTERNAL -H ldapi:/// <<'EOF'
   dn: cn=config
   replace: olcTLSCertificateFile
   olcTLSCertificateFile: /etc/openldap/tls/cert.pem
   -
   replace: olcTLSCertificateKeyFile
   olcTLSCertificateKeyFile: /etc/openldap/tls/privkey.pem
   -
   replace: olcTLSCACertificateFile
   olcTLSCACertificateFile: /etc/openldap/tls/chain.pem
   EOF
   ```

   389 Directory Server: `dsconf <instance> security certificate add` a `dsconf <instance> security set --tls-port 636`.

   **Řadič domény Active Directory**: certifikát (s klíčem, EKU *Server Authentication* a FQDN řadiče) v úložišti **Local Computer\Personal** (nebo `NTDS\Personal`); řadič ho pro StartTLS většinou převezme bez restartu - pokud ne, restartujte řadič nebo použijte `renewServerCertificate` (modify rootDSE).
2. Soubor s klíčem musí být čitelný pro uživatele serveru (`ldap` na RHEL/Alma).
3. Povolte TCP `389` z adresy acme:

   ```sh
   firewall-cmd --permanent --add-service=ldap && firewall-cmd --reload
   ```

## Vyplnění v acme

Certifikáty → **Testy** → *Přidat test* → **LDAP (StartTLS)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Connect to | jméno nebo IP adresa serveru - např. jeden uzel za load balancerem. Prázdné: první jméno certifikátu, ke kterému je test připojen (nebo adresa cíle) |
| Port | `389` |
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

1. V acme Certifikáty → **Testy**, test → **Test**: acme se připojí a požádá o StartTLS a ukáže, co server poslal - subjekt, vydavatele, platnost, jména, SHA-256, verzi TLS a šifru, délku řetězce a zda je zde důvěryhodný.
2. **Try it on a certificate** porovná, co server posílá, s certifikátem dřív, než se cokoli uloží; připojený k certifikátu se test spustí po každém nasazení (tři pokusy během půl minuty, než se služby restartují).
3. Ze stroje v síti acme totéž ručně:

```sh
openssl s_client -starttls ldap -connect ldap.example.com:389 -servername ldap.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

(`-starttls ldap` potřebuje OpenSSL 1.1.1 nebo novější.) `ldapwhoami -ZZ -H ldap://ldap.example.com -x` ověří StartTLS tak, jak by to udělal klient.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the LDAP server refused StartTLS (it said: unavailable (52) / protocolError (2))` | pro TLS není nastaven certifikát, nebo uživatel serveru nepřečte klíč |
| `Notice of Disconnection` | server ukončil relaci hned - viz jeho log; často chyba konfigurace TLS při startu |
| AD: **another certificate** | řadič vybral jiný certifikát ze svého úložiště (bere ten se Server Authentication a svým FQDN): odstraňte starý, nebo dejte certifikát acme do `NTDS\Personal`, který má přednost |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | firewall nebo ACL zahazuje acme: povolte TCP z adresy acme (nebo konektoru) na port; ověřte, že služba naslouchá na tomto rozhraní, ne jen na 127.0.0.1 |
| `... cannot be looked up` | acme nepřeloží jméno: opravte DNS, nebo dejte IP adresu do *Connect to* a jméno do *Name asked for (SNI)* |
| **an old version** | obnovení se k serveru nedostalo: služba se po nasazení nenačetla znovu, nebo jiný uzel za balancerem má stále starý soubor |
| **another certificate** | server má nastavený jiný soubor, než kam acme nasazuje, nebo SNI vybere jiný virtuální host / jiný certifikát |
| **serves it - but** no intermediate | nastavte na serveru celý řetězec (certifikát + mezilehlé), ne jen samotný certifikát |
| `the TLS handshake failed` | žádná společná verze TLS nebo šifra: zkontrolujte nastavení TLS serveru, nebo *TLS at least / at most* a *Ciphers* v testu |
