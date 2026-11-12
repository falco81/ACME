# ACME CA (Let's Encrypt a další) - nastavení pro acme

Zdroj **ACME (Let's Encrypt and others)** objednává certifikáty od libovolné CA, která mluví ACME (RFC 8555): Let's Encrypt (výchozí), ZeroSSL, Google Trust Services, Buypass, SSL.com, DigiCert, Actalis, Certum, Sectigo a podle URL adresáře HARICA, SwissSign, step-ca nebo váš vlastní ACME server. acme u CA vytvoří (nebo znovu použije) **účet**, pošle `newOrder` se všemi jmény, každé jméno prokáže validací certifikátu (DNS-01 nebo HTTP-01), dokončí objednávku vlastním CSR - **soukromý klíč nikdy neopustí acme** - a obnovuje v okně ARI, které určí CA. Na straně CA potřebujete jen vazbu účtu (EAB), kde ji CA žádá, a záznamy CAA, které CA povolují.

## Co potřebujete

- Přístup HTTPS **z acme** na ACME server CA (např. `acme-v02.api.letsencrypt.org:443`), přímo nebo přes Nastavení → Proxy.
- Validaci (Validace) pro jména: DNS-01 (API DNS poskytovatele, RFC 2136...) nebo HTTP-01 (port 80 každého jména dosažitelný z internetu).
- **Údaje EAB** (key id + HMAC klíč) pro CA, které vyžadují External Account Binding: ZeroSSL, Google, SSL.com, DigiCert, Actalis, Certum, Sectigo, HARICA - ne pro Let's Encrypt ani Buypass.
- DNS záznamy `CAA` (pokud je doména má), které CA povolují.

## Nastavení účtu u CA

1. **Let's Encrypt / Buypass**: není co nastavovat - acme účet vytvoří samo. Nejdřív zkoušejte na *Let's Encrypt staging*.
2. **ZeroSSL**: acme si EAB umí samo získat z prvního *Contact e-mail*; nebo ho vezměte z dashboardu: **Developer → EAB Credentials → Generate**.
3. **Google Trust Services**: v projektu Google Cloud zapněte Public CA API a pak

   ```sh
   gcloud publicca external-account-keys create --project=<project>
   ```

   Vypíše `keyId` a `b64MacKey`. Klíč se použije jednou, pro jeden účet.
4. **SSL.com**: stránka API údajů účtu (ACME credentials). **DigiCert CertCentral**: **Automation → ACME** → přidat ACME directory URL (produkt, organizace, platnost) → zkopírovat key id a HMAC klíč. **Sectigo**: od Sectiga (Certificate Manager: **Enrollment → ACME**). **Actalis**: zákaznická oblast → Manage with ACME → ACME Credentials. **Certum**: kid a HMAC v detailu objednávky ACME produktu. **HARICA**: CertManager (ACME) dá URL adresáře a EAB společně.
5. **step-ca** (vlastní): ACME provisioner, `step ca provisioner add acme --type ACME`; adresář je `https://ca.example.local/acme/acme/directory`; dejte acme kořen step-ca jako *CA certificate of the ACME server*.
6. Povolte CA v DNS, např. `example.com. CAA 0 issue "letsencrypt.org"` (`"sectigo.com"`, `"pki.goog"`, `"digicert.com"`...).

## Vyplnění v acme

Zdroje → **Přidat** → **ACME (Let's Encrypt and others)**.

| Pole v acme | Co do něj zadat |
|---|---|
| CA | předvolba (Let's Encrypt, ZeroSSL, Google, Buypass, SSL.com, DigiCert, Actalis, Certum, Sectigo DV/OV) nebo *Another ACME server* |
| Directory URL | s *Another ACME server*: např. `https://acme-v02.harica.gr/acme/<account id>/directory` |
| Contact e-mails | např. `pki@example.com` - e-maily o expiraci a politice; ZeroSSL ho potřebuje k vytvoření EAB |
| EAB key id / EAB HMAC key | od CA (base64url, přesně jak je zobrazen); pro Let's Encrypt prázdné |
| Account key (pokročilé) | ECDSA P-256 (výchozí); **změna vytvoří nový účet** |
| ACME profile (pokročilé) | Let's Encrypt: `classic`, `tlsserver`, `shortlived` (6denní, nutný pro IP adresy) |
| Preferred chain (pokročilé) | např. `ISRG Root X1` |
| CA certificate of the ACME server / Check the server's TLS certificate (pokročilé) | pro vlastní ACME server s privátním TLS certifikátem |
| Wait for the proof to be visible / for the CA to check / for the certificate (s), Ask again every (s) (pokročilé) | `300` / `180` / `300` / `5`; u pomalého DNS zvyšte první |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přečte adresář, najde nebo vytvoří účet; uvede nabízené profily a zda CA umí ARI.
- Nejdřív objednejte certifikát na staging CA. Ručně: `curl -s https://acme-v02.api.letsencrypt.org/directory`.

## Časté problémy

| Problém | Řešení |
|---|---|
| *this CA needs External Account Binding* | vyplňte EAB key id a HMAC klíč |
| EAB odmítnuto / `unauthorized` | HMAC je špatně zkopírovaný, nebo key id už byl použit pro jiný účet |
| *a CAA record in DNS does not allow this CA* | přidejte do záznamu CAA `0 issue "<doména CA>"` |
| *the proof ... is not visible after 300 s* | DNS-01: TXT záznam není v zóně, kterou vidí svět; zvyšte čekání |
| *the CA could not reach the server for the challenge* | HTTP-01: otevřete port 80 z internetu ke každému jménu |
| *the CA's rate limit is reached* | počkejte; zkoušejte na stagingu (Let's Encrypt: 5 certifikátů týdně pro stejná jména) |
| *the CA will not issue for this kind of name* | IP adresy u Let's Encrypt potřebují profil `shortlived` |
