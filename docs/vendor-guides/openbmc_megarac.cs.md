# OpenBMC a AMI MegaRAC - nastavení pro acme (cíl „redfish“)

BMC **OpenBMC** (bmcweb) a **AMI MegaRAC SP-X** (ASRock Rack, Gigabyte, …) přijímají HTTPS
certifikát přes **standardní Redfish** - existující cíl **Server management (Redfish: iDRAC,
iLO, XCC, BMC)** dělá přesně to, co dokumentují; vlastní modul není potřeba:

```text
POST /redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate
     {"CertificateUri": {"@odata.id": "/redfish/v1/Managers/bmc/NetworkProtocol/HTTPS/Certificates/1"},
      "CertificateString": "<nešifrovaný klíč + certifikát, PEM>", "CertificateType": "PEM"}
```

**Nastavte „Poslat jako“ na `PEM`** - bmcweb povoluje jen `PEM`
(`CertificateType@Redfish.AllowableValues: ["PEM"]`); výchozí `PEMchain` cíle odmítne.
phosphor-certificate-manager sám restartuje bmcweb (krátký výpadek webu/Redfish, relace se
zruší) - reset BMC není potřeba. Manager je u OpenBMC `bmc` (cíl ho najde sám), u MegaRAC často
`Self`.

**MegaRAC:** jen tam, kde firmware v `GET /redfish/v1/CertificateService` uvádí
`#CertificateService.ReplaceCertificate`; jinak zbývá webové GUI (**Settings → SSL Settings →
Upload SSL certificate**, ASRock Rack).

## Co potřebujete

- Uživatele s rolí **Administrator** (bmcweb nemá vlastní role; je potřeba `ConfigureManager` -
  ostatním CertificateService ReplaceCertificate ani neukáže):

  ```sh
  curl -k -u root:'<heslo>' -X POST https://bmc.example.local/redfish/v1/AccountService/Accounts \
    -H "Content-Type: application/json" \
    -d '{"UserName": "svccert", "Password": "<silné-heslo>", "RoleId": "Administrator", "Enabled": true}'
  ```

## Vyplnění v acme (cíl „Server management (Redfish …)“)

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Uživatel / Heslo | BMC, `svccert` |
| Poslat jako (nasazení) | **PEM** |
| URI certifikátu (nasazení, rozšířené) | prázdné, nebo `/redfish/v1/Managers/bmc/NetworkProtocol/HTTPS/Certificates/1` |
| Potom restartovat řadič (nasazení) | vypnuto (OpenBMC); zapnout jen u MegaRAC, který drží starý certifikát |

## Ověření

```sh
curl -k -u svccert:'<heslo>' https://bmc.example.local/redfish/v1/CertificateService/CertificateLocations
openssl s_client -connect bmc.example.local:443 -servername bmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```
