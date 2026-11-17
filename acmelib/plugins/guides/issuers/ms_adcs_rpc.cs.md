# Microsoft AD CS (RPC, jako certreq) - nastavení pro acme

Zdroj **Microsoft AD CS (RPC, as certreq)** se ptá CA služby Active Directory Certificate Services **přímo**, stejně jako `certreq.exe`: CSR vytvořené acme jde přes DCE/RPC na rozhraní CA `ICertPassage` (MS-ICPR) se šablonou, certifikát a jeho řetězec přijdou zpět. **Soukromý klíč nikdy neopustí acme.** acme se přihlašuje přes **Kerberos** (AES; výchozí) nebo **NTLMv2** a každé volání je **šifrované** (packet privacy). Žádné IIS, žádný Web Enrollment, na Windows se nic neinstaluje. Žádost, kterou šablona drží ke schválení správcem certifikátů, si acme zapamatuje a vyzvedne při dalších pokusech. Kerberos potřebuje v acme balíček Pythonu `cryptography` (python3-cryptography); NTLM ne.

## Co potřebujete

- Enterprise CA dosažitelnou **z acme** na TCP **135** (endpoint mapper) a na jejím RPC portu (**49152-65535**, nebo pevném) - a pro Kerberos řadiče domény na TCP **88**.
- Servisní účet pro acme s právy **Read** a **Enroll** na šabloně a **Request Certificates** na CA.
- **Šablonu** s *Subject Name: Supply in the request*, publikovanou na CA.
- Pro Kerberos: **plné DNS jméno** serveru CA (jméno jeho počítačového účtu), záznamy DNS SRV `_kerberos._tcp.<doména>` dosažitelné z acme (nebo zadané řadiče domény) a **hodiny acme nejvýše 5 minut** od hodin domény.

## Nastavení AD CS

1. Servisní účet, např. `svc-acme` (běžný doménový uživatel; pro Kerberos potřebuje klíče AES - u velmi starého hesla ho nastavte znovu):

   ```powershell
   New-ADUser -Name svc-acme -AccountPassword (Read-Host -AsSecureString) -Enabled $true -PasswordNeverExpires $true
   Set-ADUser svc-acme -KerberosEncryptionType AES128,AES256
   ```

2. Šablona - **certtmpl.msc** → *Web Server* → **Duplicate Template**:
   - *General*: jméno, např. `acmeWebServer` (acme potřebuje **jméno šablony**, bez mezer).
   - *Subject Name*: **Supply in the request**.
   - *Cryptography*: pro RSA i ECDSA zvolte *Key Storage Provider* (schéma 2+).
   - *Security*: `svc-acme` → **Read** a **Enroll**.
   - *Issuance Requirements*: pro automatická obnovení nechte *CA certificate manager approval* vypnuté.
3. Publikujte ji: **certsrv.msc → CA → Certificate Templates → New → Certificate Template to Issue**, nebo

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

4. Zabezpečení CA (certsrv.msc → CA → Properties → Security): `svc-acme` (nebo Authenticated Users) má **Request Certificates**.
5. Firewall serveru CA: TCP 135 a dynamický rozsah RPC z adresy acme - nebo pevný port pro *CertSrv Request* (dcomcnfg → DCOM Config → CertSrv Request → Endpoints), v acme zadaný jako *Fixed port*.
6. Jméno CA: `certutil -config -` (nebo `certutil -dump`) ukáže `ca01.example.local\EXAMPLE-CA01-CA` - acme potřebuje část za zpětným lomítkem.

## Vyplnění v acme

Zdroje → **Přidat** → **Microsoft AD CS (RPC, as certreq)**.

| Pole v acme | Co do něj zadat |
|---|---|
| CA server | `ca01.example.local` - plné DNS jméno |
| CA name | `EXAMPLE-CA01-CA` |
| Template | `acmeWebServer` - jméno, ne zobrazované jméno; vlastní šablona certifikátu má přednost |
| Signing in | *Kerberos, NTLM kde Kerberos nejde* (výchozí), *jen Kerberos*, *jen NTLM (v2)* |
| Domain | `EXAMPLE.LOCAL` (DNS jméno domény AD; prázdné: podle jména serveru CA) |
| User / Password | `svc-acme` (nebo `svc-acme@example.local`; `EXAMPLE\svc-acme` pro NTLM), jeho heslo |
| Domain controllers (KDC) (pokročilé) | `dc01.example.local` - prázdné: DNS SRV |
| Service name of the CA server (SPN) (pokročilé) | prázdné: `host/<server CA>` |
| Fixed port (pokročilé) | pevný RPC port CA; prázdné: zjistí se z endpoint mapperu |
| More attributes / CA chain (pokročilé) | další atributy žádosti; řetězec CA, když ho odpověď CA nenese |
| Key types the template takes | *RSA and ECDSA* (šablona s KSP), *RSA only*, *ECDSA only* |

## Ověření

- Zdroje → zdroj → **Test** (Try it): endpoint mapper, přihlášení a bind - řekne port, jak se přihlásil (Kerberos AES256 nebo NTLMv2) a že je spojení šifrované; o certifikát nežádá.
- Na CA: `certutil -view -restrict "RequesterName=EXAMPLE\svc-acme" -out "RequestID,CommonName,Disposition"`.

## Časté problémy

| Problém | Řešení |
|---|---|
| nelze se spojit s …:135 | firewall: TCP 135 a rozsah RPC (nebo pevný port) |
| endpoint mapper nezná ICertPassage | CertSvc tam neběží, nebo to není server CA |
| doména nezná službu host/… | plné DNS jméno serveru CA (ne alias ani adresa), nebo SPN v pokročilých |
| hodiny se liší o N minut | NTP v acme nasměrované na řadič domény |
| špatné heslo / access is denied (NTLM) | uživatel a heslo; zamčený účet |
| `0x80094012` - nesmí žádat o tuto šablonu | šablona → Security: Read + Enroll pro účet |
| `0x80094011` - oprávnění CA | CA → Properties → Security: Request Certificates |
| `0x80094800` - CA tuto šablonu nenabízí | publikujte ji na CA; jméno šablony |
| `0x80070057` | jméno CA (za zpětným lomítkem v `certutil -config`) |
| Žádost čeká | schvalte ji v certsrv.msc → Pending Requests; u certifikátu nastavte **Keep the key** |

Vyzkoušeno proti testovacím vektorům protokolů, MIT Kerberu a simulovaným serverům - ne proti skutečné Windows CA; viz `docs/ms-adcs-rpc.md`.
