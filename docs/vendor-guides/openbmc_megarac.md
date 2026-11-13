# OpenBMC and AMI MegaRAC - setup for acme (target "redfish")

**OpenBMC** (bmcweb) and **AMI MegaRAC SP-X** BMCs (ASRock Rack, Gigabyte, …) take the HTTPS
certificate through **standard Redfish** - the existing target **Server management (Redfish:
iDRAC, iLO, XCC, BMC)** does exactly what they document; no module of their own is needed:

```text
POST /redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate
     {"CertificateUri": {"@odata.id": "/redfish/v1/Managers/bmc/NetworkProtocol/HTTPS/Certificates/1"},
      "CertificateString": "<unencrypted key + certificate, PEM>", "CertificateType": "PEM"}
```

**Set "Send as" to `PEM`** - bmcweb allows `PEM` only (`CertificateType@Redfish.AllowableValues:
["PEM"]`); the target's default `PEMchain` is refused. phosphor-certificate-manager restarts
bmcweb by itself (a short break of web/Redfish, sessions dropped) - no BMC reset needed. The
manager is `bmc` on OpenBMC (found by itself), often `Self` on MegaRAC.

**MegaRAC:** only where the firmware lists `#CertificateService.ReplaceCertificate` in `GET
/redfish/v1/CertificateService`; otherwise the web GUI (**Settings → SSL Settings → Upload SSL
certificate**, ASRock Rack) is the only way.

## What you need

- A user with the role **Administrator** (bmcweb has no custom roles; `ConfigureManager` is
  needed - the CertificateService even hides ReplaceCertificate from others):

  ```sh
  curl -k -u root:'<password>' -X POST https://bmc.example.local/redfish/v1/AccountService/Accounts \
    -H "Content-Type: application/json" \
    -d '{"UserName": "svccert", "Password": "<strong-password>", "RoleId": "Administrator", "Enabled": true}'
  ```

## Fill in acme (target "Server management (Redfish …)")

| acme field | What to put there |
|---|---|
| Address / User / Password | the BMC, `svccert` |
| Send as (deploy) | **PEM** |
| Certificate URI (deploy, advanced) | empty, or `/redfish/v1/Managers/bmc/NetworkProtocol/HTTPS/Certificates/1` |
| Restart the controller afterwards (deploy) | off (OpenBMC); on only for a MegaRAC that keeps the old one |

## Check it

```sh
curl -k -u svccert:'<password>' https://bmc.example.local/redfish/v1/CertificateService/CertificateLocations
openssl s_client -connect bmc.example.local:443 -servername bmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```
