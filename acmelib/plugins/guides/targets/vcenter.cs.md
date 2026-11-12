# VMware vCenter Server - nastavení pro acme

acme používá vSphere Automation REST API: přihlásí se (`POST /api/session`, základní
autentizace), přidá mezilehlé certifikáty a kořen do **důvěryhodných kořenových řetězců**
vCenteru (`/api/vcenter/certificate-management/vcenter/trusted-root-chains`) a pak
**vymění certifikát machine SSL** - ten, který používá vSphere Client
(`PUT /api/vcenter/certificate-management/vcenter/tls` s `cert`, `key`, `root_cert`).
**vCenter pak restartuje své služby: vSphere Client je několik minut nedostupný.** Kontrola
acme na to počká (20 pokusů po 15 s). Má-li vCenter tento certifikát už nasazený, nic se
nedělá.

Pro vCenter Server 7.0 a novější (včetně 8.x). Hostitelé ESXi mají vlastní cíl (`esxi`).

## Co potřebujete

- Síťový přístup z acme na vCenter: **TCP 443**.
- Uživatele SSO s oprávněním **CertificateManagement.Administer** (mají ho členové
  *Administrators* v `vsphere.local`).
- U Let's Encrypt a jiných řetězců bez kořene: **kořenový certifikát CA** v PEM (pro
  Let's Encrypt ISRG Root X1).
- Servisní okno: každé obnovení restartuje služby vCenteru.

## Nastavení vCenteru

1. Vytvořte samostatného uživatele SSO: **vSphere Client → Administration → Single Sign On →
   Users and Groups → Users** → doména `vsphere.local` → **Add**, např. `acme`.
2. Dejte mu oprávnění k certifikátům, buď:
   - **Administration → Access Control → Roles → New**: role jen s **Certificate
     Management → Create/Delete (Admins priv)** (`CertificateManagement.Administer`); pak
     **Administration → Access Control → Global Permissions → Add**: uživatel
     `acme@vsphere.local`, tato role, *Propagate to children*; nebo
   - ho prostě přidejte do skupiny **Administrators** (širší).

   Pokud je výměna jen s rolí stále odmítnuta, použijte člena *Administrators*, jak
   popisuje dokumentace Broadcomu.
3. Stáhněte kořenový certifikát CA, kterým řetězec končí (pro Let's Encrypt ISRG Root X1 z
   letsencrypt.org) - vloží se do *Root CA certificate*.
4. Používá-li vCenter vlastní režim CA nebo zásady VMCA, ověřte, že vlastní certifikát
   machine SSL přijme (**Administration → Certificates → Certificate Management**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | FQDN vCenteru, např. `vcenter.example.local` |
| HTTPS port | `443` |
| User | `acme@vsphere.local` (výchozí `administrator@vsphere.local`) |
| Password | Jeho heslo |
| Check the device's certificate | Zapnuto; dokud má vCenter certifikát od VMCA, vložte kořen VMCA do *CA certificate* |
| CA certificate (pokročilé) | Kořen VMCA (ke stažení z `https://<vcenter>/certs/download.zip`) |
| Root CA certificate (nasazení) | Kořenový PEM (pro Let's Encrypt ISRG Root X1); prázdné: poslední certifikát řetězce |
| Add the chain to the trusted roots (nasazení) | Zapnuto (výchozí) - vCenter přijme certifikát, jen když důvěřuje vydavatelům |
| Check what is served | Prázdné: acme ověří vlastní adresu vCenteru |

**Certifikát musí obsahovat FQDN vCenteru** (Primary Network Identifier) a mít klíč RSA
(2048 a více).

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí a přečte současný certifikát:
  `signed in to ...; its certificate: <subjekt>, valid to <datum>`.
- Po nasazení (až služby znovu naběhnou): **Administration → Certificates → Certificate
  Management → Machine SSL Certificate** ukazuje nový certifikát; nebo

  ```sh
  openssl s_client -connect vcenter.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatné jméno/heslo; použijte tvar `user@vsphere.local`. |
| `403` / Unauthorized při výměně | Uživatel nemá `CertificateManagement.Administer`; přidejte ho do *Administrators*. |
| `400` kvůli řetězci / nedůvěryhodný | Vyplňte *Root CA certificate* a nechte zapnuté *Add the chain to the trusted roots*. |
| `400` neplatný certifikát | Klíč není RSA, nebo certifikát neobsahuje FQDN vCenteru. |
| Kontrola hned po nasazení selže | Služby se ještě restartují; acme zkouší asi 5 minut. |
