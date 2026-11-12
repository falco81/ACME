# Správcovské řadiče serverů (Redfish) - nastavení pro acme

acme vymění **HTTPS certifikát správcovského řadiče serveru** (Dell iDRAC, HPE iLO, Lenovo
XClarity Controller, BMC Supermicro a AMI MegaRAC) přes standardní Redfish. Přihlásí se
relací (`POST` na session service, `X-Auth-Token`; nebo základní autentizací), najde
první položku `NetworkProtocol/HTTPS/Certificates` prvního manageru (nebo zadané
*Certificate URI*) a zavolá `CertificateService.ReplaceCertificate` s klíčem a
certifikátem v jednom řetězci PEM (`PEMchain`: klíč + celý řetězec, nebo `PEM`: klíč +
certifikát). Je-li kolekce prázdná, certifikát do ní pošle `POST`em. S volbou *Restart the
controller afterwards* pošle `Manager.Reset` `GracefulRestart` - **restartuje se jen
řadič, ne server**.

**Které řadiče takto přijmou soukromý klíč, se liší.** Podle hlášení fungují: AMI MegaRAC
(ASUS, Lenovo, Supermicro), Dell iDRAC9 s firmwarem 5.x a novějším, HPE iLO 5 2.42 a
novější. **HPE iLO 6 nabízí jen GenerateCSR** a klíč nepřijme - acme to oznámí. Starší
iDRAC potřebují `racadm sslkeyupload`, ne tento cíl. Lenovo XCC2 bere jen `PEM`.
Pro certifikát použijte typ klíče **RSA 2048**.

## Co potřebujete

- Síťový přístup z acme na HTTPS řadiče: **TCP 443**.
- Zapnutý Redfish na řadiči.
- Uživatele řadiče s oprávněním **Configure Manager** (iDRAC: *Configure*; iLO:
  *Configure iLO Settings*).

## Nastavení řadiče

1. Zapněte Redfish, je-li vypnutý.
   - iDRAC: **iDRAC Settings → Services → Redfish → Enabled**, nebo:

     ```text
     racadm set iDRAC.Redfish.Enable 1
     ```
   - iLO: Redfish je součástí iLO RESTful API a je ve výchozím stavu zapnutý.
2. Vytvořte pro acme samostatného uživatele jen s právy *Login* a *Configure*:
   - iDRAC: **iDRAC Settings → Users → Local Users → Add**, vlastní role s *Login* a
     *Configure*. Přes racadm (slot 3 je příklad - použijte volný):

     ```text
     racadm set iDRAC.Users.3.UserName acme
     racadm set iDRAC.Users.3.Password <silne-heslo>
     racadm set iDRAC.Users.3.Privilege 0x3
     racadm set iDRAC.Users.3.Enable 1
     ```

     (`0x3` = Login + Configure iDRAC.)
   - iLO: **Administration → User Administration → New**, oprávnění *Login* a *Configure
     iLO Settings*.
   - XCC / Supermicro / MegaRAC: uživatel s rolí, která smí měnit konfiguraci/bezpečnostní
     nastavení BMC (ověřte v seznamu rolí svého výrobce).
3. Má-li řadič omezení IP adres (iDRAC *IP Blocking / IP Range*, iLO *Access Settings*),
   zahrňte do něj server acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP řadiče, např. `idrac.example.local` |
| HTTPS port | `443` |
| User / Password | Uživatel acme z kroku 2 |
| Basic authentication instead of a session (pokročilé) | Jen pro řadič, kterému nefungují relace |
| Check the device's certificate | Zapnuto; vypnout jen dokud má řadič self-signed certifikát (typicky při prvním nasazení) |
| CA certificate (pokročilé) | CA současného certifikátu řadiče, pokud není veřejná |
| Send as (nasazení) | *PEMchain* (výchozí); *PEM* pro řadič, který ho odmítá (Lenovo XCC2) |
| Certificate URI (nasazení, pokročilé) | Prázdné: první HTTPS certifikát prvního manageru. Nebo např. `/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates/SecurityCertificate.1` |
| Restart the controller afterwards (nasazení) | Zapnout pro iDRAC (nový certifikát použije až po resetu) |
| Check what is served | Prázdné: acme ověří vlastní adresu řadiče |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, přečte manager a odpoví
  `signed in to ...: <výrobce> <model>, firmware x, Redfish y`.
- Z libovolného počítače:

  ```sh
  curl -sk -u acme:'<heslo>' https://idrac.example.local/redfish/v1/CertificateService
  openssl s_client -connect idrac.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

  První příkaz by měl v `Actions` uvádět `#CertificateService.ReplaceCertificate`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatné jméno/heslo, vypnutý uživatel, nebo vypnutý Redfish. |
| `403` při výměně | Uživateli chybí *Configure* / *Configure iLO Settings*. |
| `offers no CertificateService.ReplaceCertificate` | HPE iLO 6: bere jen certifikáty k vlastnímu CSR - nepodporováno. |
| Certifikát odmítnut | Zkuste *Send as* `PEM`; použijte klíč RSA 2048; starší firmware nemusí klíč přijmout vůbec - aktualizujte ho. |
| Řadič stále ukazuje starý certifikát | Zapněte *Restart the controller afterwards* (iDRAC); kontrola na restart počká. |
| Dosažen limit relací | Na řadiči je otevřeno příliš relací; počkejte, nebo použijte základní autentizaci. |
