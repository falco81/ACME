# SCEP server (NDES, EJBCA, step-ca...) - nastavení pro acme

Zdroj **SCEP (NDES, EJBCA, step-ca, ...)** získává certifikáty od libovolné CA, která mluví SCEP (RFC 8894): Microsoft NDES, EJBCA, Smallstep step-ca, Cisco IOS, FortiAuthenticator, Palo Alto, Jamf, OpenXPKI. acme se zeptá `GetCACaps` a `GetCACert`, pak pošle `PKIOperation` **PKCSReq**: vlastní CSR s *challenge password*, zašifrované pro certifikát CA/RA a podepsané krátkodobým self-signed certifikátem klíče žádosti. Na odpověď **PENDING** se dotazuje přes CertPoll a znovu při dalších pokusech. **Soukromý klíč nikdy neopustí acme**; SCEP potřebuje klíč **RSA** (2048+) - ne ECDSA.

## Co potřebujete

- SCEP URL dosažitelnou **z acme** (HTTP nebo HTTPS, často port 80).
- **Challenge password**, které CA přijme - a pro automatická obnovení takové, které po jednom použití nevyprší.
- **Otisk certifikátu CA** (SHA-256): SCEP často běží přes čisté HTTP a právě otisk chrání před někým uprostřed.
- Certifikáty s klíčem RSA v acme.

## Nastavení SCEP serveru

**Microsoft NDES** (Windows Server, role *Network Device Enrollment Service*):

1. Šablona, ze které NDES vydává, je v registru `HKLM\Software\Microsoft\Cryptography\MSCEP` (`EncryptionTemplate`, `GeneralPurposeTemplate`, `SignatureTemplate`): nastavte je na šablonu se *Subject Name: Supply in the request* (kopie *Web Server*), na které má servisní účet NDES Read + Enroll, publikovanou na CA.
2. Challenge z `https://ndes.example.local/certsrv/mscep_admin` je **jednorázové a vyprší** (výchozí 60 minut). Pro automatická obnovení použijte pevné heslo:

   ```powershell
   $k = 'HKLM:\Software\Microsoft\Cryptography\MSCEP'
   New-Item "$k\UseSinglePassword" -Force | Out-Null
   Set-ItemProperty "$k\UseSinglePassword" -Name UseSinglePassword -Value 1 -Type DWord
   Set-ItemProperty "$k\UseSinglePassword" -Name Password -Value '<long random password>'
   iisreset
   ```

   (nebo `EnforcePassword` = 0 jen v uzavřené síti). Přesné uspořádání registru pro vaši verzi Windows ověřte v dokumentaci NDES od Microsoftu.

**EJBCA**: System Configuration → SCEP Configuration → přidat alias (režim RA, profily entity / certifikátu); URL je `.../ejbca/publicweb/apply/scep/<alias>/pkiclient.exe`; challenge je enrollment code entity (nebo heslo RA autentizace aliasu).

**step-ca**: SCEP provisioner s challenge:

```sh
step ca provisioner add scep-acme --type SCEP --challenge '<secret>'
```

URL `https://ca.example.local/scep/scep-acme`.

Otisk certifikátu CA:

```sh
curl -s 'http://ndes.example.local/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACert' -o ca.p7b
openssl pkcs7 -inform DER -in ca.p7b -print_certs | openssl x509 -noout -fingerprint -sha256
```

(NDES posílá i certifikáty RA - vezměte otisk certifikátu CA.)

## Vyplnění v acme

Zdroje → **Přidat** → **SCEP (NDES, EJBCA, step-ca, ...)**.

| Pole v acme | Co do něj zadat |
|---|---|
| SCEP address | NDES `https://ndes.example.local/certsrv/mscep/mscep.dll`; EJBCA `.../ejbca/publicweb/apply/scep/<alias>/pkiclient.exe`; step-ca `https://ca.example.local/scep/<provisioner>` |
| Challenge password | NDES: pevné heslo (nebo heslo z `mscep_admin`); EJBCA: enrollment code; step-ca: challenge provisioneru |
| CA fingerprint | SHA-256 certifikátu CA - **vyplňte ho** |
| CA identifier (pokročilé) | kde jeden server hostí více CA (EJBCA: jméno CA) |
| Encryption / Digest (pokročilé) | *As the CA says*; 3DES / SHA-1 jen pro staré servery |
| CA certificate of the web server / Check the web server's TLS certificate (pokročilé) | pro HTTPS s privátní CA |
| Wait for approval (s) / Ask again every (s) (pokročilé) | `60` / `10` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): GetCACaps a GetCACert, CA zkontrolovaná proti otisku.
- Ručně: `curl 'http://ndes.example.local/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACaps'`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `... badRequest` | challenge password je špatné, použité nebo vypršelé; nebo CA nepovoluje jména |
| `... badMessageCheck` | server nedokázal ověřit podpis nebo dešifrovat - změnil se certifikát RA? |
| `... badAlg` | v pokročilých nastaveních zvolte 3DES / SHA-1 (staré servery) |
| `... badTime` | hodiny acme |
| the CA certificate is not the one of the fingerprint | někdo uprostřed, nebo byla CA obnovena: porovnejte a nastavte nový otisk |
| SCEP needs an RSA key | nastavte typ klíče certifikátu na RSA |
| Obnovení na NDES selhávají, první vydání prošlo | jednorázové heslo vypršelo: použijte `UseSinglePassword` |
