# Vlastní certifikační autorita - nastavení pro acme

Zdroj **Own certificate authority** nechá certifikát okamžitě podepsat jednou z vlastních certifikačních autorit acme (Nastavení → Autority): pro interní jména (`*.corp.local`), privátní IP adresy, zařízení a klienty, servery, které se nesmějí objevit v Certificate Transparency. Nic neopouští acme - autorita, její klíč i podepisování jsou uvnitř. Protějškem k nastavení je **každý klient, který má certifikátům důvěřovat**: potřebuje kořen autority.

## Co potřebujete

- Autoritu v acme: Nastavení → Autority (vyžaduje roli `fulladmin`). Zamýšlená podoba je kořen (podepisuje jen mezilehlé) a pod ním vydávající mezilehlá autorita, která podepisuje servery.
- Způsob, jak dostat kořenový certifikát do úložišť důvěryhodných certifikátů klientů: Group Policy, MDM, správa konfigurace, Java truststore.
- Kde klienti kontrolují odvolání: adresa CRL vložená do certifikátů pro ně musí být dosažitelná (acme publikuje CRL na `http://<acme>/pki/`, když je zapnuté *Publish on acme*).

## Nastavení autority a klientů

1. V acme Nastavení → Autority → vytvořte **kořen** (např. `ec-384`, 10-20 let, path length 1), pak **vydávající CA** s kořenem jako *Parent* (path length 0). Přidejte *Name constraints* (např. `corp.example`, `IP:10.0.0.0/8`), abyste omezili, co smí podepsat. Nebo vytvořte mezilehlou autoritu *pod CA jinde* (váš kořen AD CS) - pak se nemusí důvěřovat ničemu novému.
2. Stáhněte certifikát kořene (autorita → `cert` / `cert-der`) a rozdistribuujte ho:

   ```powershell
   # jeden stroj s Windows (Group Policy: Computer Configuration → Policies → Windows Settings →
   # Security Settings → Public Key Policies → Trusted Root Certification Authorities → Import)
   Import-Certificate -FilePath .\corp-root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

   ```sh
   cp corp-root.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust          # rodina RHEL
   cp corp-root.pem /usr/local/share/ca-certificates/corp-root.crt && update-ca-certificates   # Debian
   keytool -importcert -cacerts -alias corp-root -file corp-root.pem              # Java
   ```

3. Servery musí se svým certifikátem posílat i **mezilehlý** (acme k němu přikládá řetězec; nasazujte celý řetězec).
4. Kde klienti kontrolují odvolání, umožněte jim dosáhnout na adresy CRL / certifikátu CA (HTTP na acme, port 80).

## Vyplnění v acme

Zdroje → **Přidat** → **Own certificate authority**.

| Pole v acme | Co do něj zadat |
|---|---|
| Certificate authority | autorita, která podepisuje - vydávající mezilehlá, ne kořen |
| Validity (days) | `397` (výchozí); nikdy ne za konec platnosti samotné autority |
| Extended key usage (pokročilé) | `serverAuth`, `clientAuth` (výchozí); `codeSigning`, `emailProtection` nebo OID |

Wildcardy, IP adresy, klíče RSA i ECDSA jsou povoleny. *Certifikáty → Import from a source* vypíše, co autorita podepsala.

## Ověření

- Zdroje → zdroj → **Test** (Try it).
- Na klientovi, který má kořen:

```sh
openssl verify -CAfile corp-root.pem -untrusted issuing-ca.pem server.pem
openssl s_client -connect www.corp.example:443 -servername www.corp.example </dev/null | grep 'Verify return code'
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `unable to get local issuer certificate` na klientovi | kořen není v úložišti klienta, nebo server neposílá mezilehlý certifikát |
| Jméno je odmítnuto před podpisem | je mimo *Name constraints* autority |
| Platnost je kratší, než se žádalo | je oříznuta koncem platnosti autority; autoritu obnovte včas |
| Prohlížeče odmítají dlouho platný certifikát | serverové certifikáty držte nejvýš na 397 dnech |
| Kontrola odvolání na klientech selhává | adresa CRL pro ně není dosažitelná (port 80 na acme, nebo vlastní adresa CRL) |
