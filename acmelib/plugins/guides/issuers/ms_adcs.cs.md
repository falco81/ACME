# Microsoft AD CS (Web Enrollment) - nastavení pro acme

Zdroj **Microsoft AD CS (Web Enrollment)** získává certifikáty od CA služby Active Directory Certificate Services přes její stránky **Web Enrollment** (`/certsrv`), stejně jako prohlížeč: CSR vytvořené acme se pošle na `certfnsh.asp` se šablonou, certifikát se stáhne z `certnew.cer` a řetězec z `certnew.p7b`. **Soukromý klíč nikdy neopustí acme.** Žádost, kterou šablona drží ke schválení správcem certifikátů, si acme zapamatuje a vyzvedne při dalších pokusech. acme se přihlašuje přes **Windows (NTLMv2)**, **Basic** přes HTTPS, nebo **klientským certifikátem**. Windows Server 2012 R2 - 2025. Webové služby CES/CEP se nepodporují; weby jen s Kerberem nejsou podporovány.

## Co potřebujete

- Enterprise CA s nainstalovanou rolí **Certification Authority Web Enrollment** (IIS, `/certsrv`), dosažitelnou **z acme** přes HTTPS (`443`) - spojení NTLM a s klientským certifikátem jdou přímo, ne přes Nastavení → Proxy.
- Servisní účet pro acme s právy **Read** a **Enroll** na šabloně a **Request Certificates** na CA.
- **Šablonu** s *Subject Name: Supply in the request*, publikovanou na CA.
- Interní kořen, který podepsal IIS certifikát CA (pro *CA certificate of the web server*).

## Nastavení AD CS

1. Nainstalujte Web Enrollment (na CA nebo jiný server):

   ```powershell
   Install-WindowsFeature ADCS-Web-Enrollment
   Install-AdcsWebEnrollment -Force
   ```

   Dejte `Default Web Site` HTTPS binding s certifikátem (Web Enrollment chce HTTPS).
2. Servisní účet, např. `svc-acme` (běžný doménový uživatel; heslo, které nevyprší, nebo ho měňte i v acme):

   ```powershell
   New-ADUser -Name svc-acme -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   ```

3. Šablona - **certtmpl.msc** → *Web Server* → **Duplicate Template**:
   - *General*: jméno, např. `acmeWebServer` (acme potřebuje **jméno šablony**, bez mezer).
   - *Subject Name*: **Supply in the request**.
   - *Cryptography*: pro RSA i ECDSA zvolte *Key Storage Provider* (schéma 2+); minimální velikost klíče podle vaší politiky.
   - *Security*: `svc-acme` → **Read** a **Enroll** (ne Autoenroll).
   - *Issuance Requirements*: pro automatická obnovení nechte *CA certificate manager approval* vypnuté.
4. Publikujte ji: **certsrv.msc → CA → Certificate Templates → New → Certificate Template to Issue**, nebo

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

5. Autentizace IIS pro `/certsrv` (**IIS Manager → Default Web Site → CertSrv → Authentication**): pro NTLM zapnuté *Windows Authentication* (poskytovatelé Negotiate a NTLM); nebo *Basic Authentication* (jen HTTPS); nebo *SSL Settings: Require* klientské certifikáty s mapováním na `svc-acme`.
6. Zabezpečení CA (certsrv.msc → CA → Properties → Security): `svc-acme` (nebo Authenticated Users) má **Request Certificates**.

## Vyplnění v acme

Zdroje → **Přidat** → **Microsoft AD CS (Web Enrollment)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Web Enrollment address | `https://ca01.example.local/certsrv` |
| Template | `acmeWebServer` - jméno, ne zobrazované jméno; *Load the list* načte, co CA uživateli nabízí; vlastní šablona certifikátu má přednost |
| Signing in | *Windows (NTLM)*, *Basic (over HTTPS)* nebo *Client certificate* |
| User / Password / Domain | `svc-acme` (nebo `EXAMPLE\svc-acme`), jeho heslo, NetBIOS jméno domény (prázdné: jak řekne server) |
| Client certificate / its key | pro přihlášení klientským certifikátem |
| CA certificate of the web server (pokročilé) | váš interní kořen, pro TLS IIS |
| Check the web server's TLS certificate (pokročilé) | zapnuto |
| More attributes (pokročilé) | další řádky `CertAttrib`, např. `SAN:dns=www.example.com` (jen kde to CA dovoluje) |
| Key types the template takes | *RSA and ECDSA* (šablona s KSP), *RSA only* (schéma 1, např. původní WebServer), *ECDSA only* |
| Wait for approval (s) (pokročilé) | `0`; čekající žádost se vyzvedne při dalších pokusech |

## Ověření

- Zdroje → zdroj → **Test** (Try it) a *Load the list* u *Template* - musí vypsat vaši šablonu.
- Na CA: `certutil -view -restrict "RequesterName=EXAMPLE\svc-acme" -out "RequestID,CommonName,Disposition"`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `0x80094800` - CA tuto šablonu nenabízí | publikujte ji na CA; zadejte jméno šablony, ne zobrazované jméno |
| `0x80094012` - uživatel nesmí žádat | šablona → Security: Read + Enroll pro uživatele |
| `0x80094005` / `0x80094004` - jména odmítnuta | šablona → Subject Name: Supply in the request |
| `0x80094009` - klíč je příliš malý | větší typ klíče, nebo snižte minimum šablony |
| `401` | uživatel, heslo, doména; zapnuté Windows Authentication pro `/certsrv`; poskytovatelé jen s Kerberem nefungují - přidejte NTLM |
| ECDSA odmítnuto | šablona používá starý CSP (schéma 1): nastavte *Key types* na RSA only, nebo vytvořte šablonu s KSP |
| Žádost čeká | schvalte ji v certsrv.msc → Pending Requests; u certifikátu nastavte **Keep the key** |
